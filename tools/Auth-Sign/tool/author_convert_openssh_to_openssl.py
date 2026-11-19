#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""author_convert_openssh_to_openssl.py

把 OpenSSH 格式的 Ed25519 密钥转换为 OpenSSL PEM 格式。

    私钥  -----BEGIN OPENSSH PRIVATE KEY-----  ->  -----BEGIN PRIVATE KEY-----  (PKCS#8)
    公钥  ssh-ed25519 AAAA...                  ->  -----BEGIN PUBLIC KEY-----   (SPKI)

约束:
    只支持 Ed25519;只支持无口令(cipher 为 none)的 OpenSSH 私钥。
    只使用 Python 标准库,不依赖 cryptography 等第三方模块。
    转换后自动用 openssl 做自校验,自校验失败则以非零退出码结束。

用法:
    python author_convert_openssh_to_openssl.py <输入文件> [-o <输出文件>]
"""

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROG = "author_convert_openssh_to_openssl.py"

SSH_MAGIC = b"openssh-key-v1\x00"
SSH_KEYTYPE = b"ssh-ed25519"
OID_ED25519 = b"\x06\x03\x2b\x65\x70"
PEM_RE = re.compile(r"-----BEGIN ([A-Za-z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)


class ConvertError(Exception):
    """转换或自校验失败。"""


def force_utf8():
    """统一用 UTF-8 输出,避免 Windows 控制台默认代码页把中文状态行写成乱码。"""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def der_tlv(tag, content):
    """按 DER 规则封装一个 TLV。"""
    n = len(content)
    if n < 0x80:
        head = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + head + content


def der_read(buf, pos, want_tag, what):
    """从 buf[pos] 起读一个 TLV,返回 (内容, 下一个位置)。"""
    if pos + 2 > len(buf):
        raise ConvertError("DER 结构被截断:%s" % what)
    tag = buf[pos]
    if tag != want_tag:
        raise ConvertError("DER 标签不符:%s 期望 0x%02X,实际 0x%02X" % (what, want_tag, tag))
    first = buf[pos + 1]
    pos += 2
    if first & 0x80:
        k = first & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            raise ConvertError("DER 长度字段非法:%s" % what)
        length = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    else:
        length = first
    end = pos + length
    if end > len(buf):
        raise ConvertError("DER 结构被截断:%s" % what)
    return buf[pos:end], end


def ssh_read_string(buf, pos, what):
    """读 openssh 的 uint32 长度前缀字符串。"""
    if pos + 4 > len(buf):
        raise ConvertError("OpenSSH 结构被截断:%s" % what)
    n = int.from_bytes(buf[pos:pos + 4], "big")
    pos += 4
    if n > len(buf) - pos:
        raise ConvertError("OpenSSH 字符串长度越界:%s" % what)
    return buf[pos:pos + n], pos + n


def ssh_string(data):
    """按 openssh 约定封装 uint32 长度前缀字符串。"""
    return len(data).to_bytes(4, "big") + data


def pem_encode(label, der):
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


def pem_decode(text):
    match = PEM_RE.search(text)
    if not match:
        raise ConvertError("输入不是 PEM 编码的密钥文件")
    label = match.group(1).strip()
    body = "".join(match.group(2).split())
    try:
        der = base64.b64decode(body, validate=True)
    except Exception:
        raise ConvertError("PEM 主体不是合法的 base64")
    return label, der


def parse_openssh_private(der):
    """解析无口令的 openssh-key-v1 私钥,返回 (seed, pub)。"""
    if not der.startswith(SSH_MAGIC):
        raise ConvertError("不是 openssh-key-v1 结构")
    pos = len(SSH_MAGIC)
    cipher, pos = ssh_read_string(der, pos, "ciphername")
    kdf, pos = ssh_read_string(der, pos, "kdfname")
    kdfopts, pos = ssh_read_string(der, pos, "kdfoptions")
    if cipher != b"none":
        raise ConvertError(
            "该 OpenSSH 私钥带口令(cipher=%s),本脚本只支持无口令私钥;"
            "请先执行 ssh-keygen -p -N \"\" -f <私钥文件> 去掉口令后重试"
            % cipher.decode("ascii", "replace"))
    if kdf != b"none" or kdfopts:
        raise ConvertError("cipher 为 none 但 kdf 不是 none,私钥结构异常")
    if pos + 4 > len(der):
        raise ConvertError("OpenSSH 结构被截断:公钥数量")
    nkeys = int.from_bytes(der[pos:pos + 4], "big")
    pos += 4
    if nkeys != 1:
        raise ConvertError("只支持单密钥文件,该文件包含 %d 个密钥" % nkeys)
    pub_outer, pos = ssh_read_string(der, pos, "public key")
    priv_blob, pos = ssh_read_string(der, pos, "private section")
    if pos != len(der):
        raise ConvertError("OpenSSH 私钥末尾有多余数据")

    if len(priv_blob) < 8:
        raise ConvertError("OpenSSH 私钥的私有段被截断")
    check1 = int.from_bytes(priv_blob[0:4], "big")
    check2 = int.from_bytes(priv_blob[4:8], "big")
    if check1 != check2:
        raise ConvertError(
            "checkint 两半不一致(0x%08X 与 0x%08X),私钥可能已损坏或被篡改" % (check1, check2))

    p = 8
    keytype, p = ssh_read_string(priv_blob, p, "keytype")
    if keytype != SSH_KEYTYPE:
        raise ConvertError("只支持 Ed25519,私钥类型是 %s" % keytype.decode("ascii", "replace"))
    pub, p = ssh_read_string(priv_blob, p, "public key")
    priv, p = ssh_read_string(priv_blob, p, "private key")
    _comment, p = ssh_read_string(priv_blob, p, "comment")

    if len(pub) != 32:
        raise ConvertError("Ed25519 公钥长度应为 32 字节,实际 %d" % len(pub))
    if len(priv) != 64:
        raise ConvertError("Ed25519 私钥长度应为 64 字节,实际 %d" % len(priv))
    if priv[32:] != pub:
        raise ConvertError("私钥后半段与公钥字段不一致,私钥可能已损坏")
    if pub_outer != ssh_string(SSH_KEYTYPE) + ssh_string(pub):
        raise ConvertError("外层公钥与私有段内的公钥不一致")

    pad = priv_blob[p:]
    if pad != bytes(range(1, len(pad) + 1)):
        raise ConvertError("填充字节不符合 openssh-key-v1 约定")
    return priv[:32], pub


def parse_openssh_public(text):
    """解析一行 ssh-ed25519 AAAA...,返回 32 字节公钥。"""
    fields = text.split()
    if len(fields) < 2:
        raise ConvertError("ssh-ed25519 公钥行格式不正确")
    if fields[0] != "ssh-ed25519":
        raise ConvertError("只支持 Ed25519,输入公钥类型是 %s" % fields[0])
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except Exception:
        raise ConvertError("公钥主体不是合法的 base64")
    keytype, pos = ssh_read_string(blob, 0, "keytype")
    if keytype != SSH_KEYTYPE:
        raise ConvertError("公钥 blob 中的类型是 %s,不是 ssh-ed25519"
                           % keytype.decode("ascii", "replace"))
    pub, pos = ssh_read_string(blob, pos, "public key")
    if pos != len(blob):
        raise ConvertError("公钥 blob 末尾有多余数据")
    if len(pub) != 32:
        raise ConvertError("Ed25519 公钥长度应为 32 字节,实际 %d" % len(pub))
    return pub


def build_pkcs8(seed):
    """RFC 8410 的 Ed25519 PrivateKeyInfo。"""
    inner = der_tlv(0x04, seed)
    return der_tlv(
        0x30,
        der_tlv(0x02, b"\x00") + der_tlv(0x30, OID_ED25519) + der_tlv(0x04, inner))


def build_spki(pub):
    """RFC 8410 的 Ed25519 SubjectPublicKeyInfo。"""
    return der_tlv(0x30, der_tlv(0x30, OID_ED25519) + der_tlv(0x03, b"\x00" + pub))


def run_openssl(args):
    exe = shutil.which("openssl")
    if not exe:
        raise ConvertError("找不到 openssl 命令,无法完成转换后的自校验")
    proc = subprocess.run([exe] + list(args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise ConvertError("openssl 执行失败(%s):%s" % (
            " ".join(args), proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout


def spki_public_key(der):
    """从 SPKI DER 中取出 32 字节 Ed25519 公钥。"""
    seq, end = der_read(der, 0, 0x30, "SPKI")
    if end != len(der):
        raise ConvertError("SPKI 末尾有多余数据")
    algid, p = der_read(seq, 0, 0x30, "SPKI algorithm")
    oid, _ = der_read(algid, 0, 0x06, "SPKI algorithm oid")
    if oid != OID_ED25519[2:]:
        raise ConvertError("openssl 输出的公钥不是 Ed25519")
    bits, p = der_read(seq, p, 0x03, "SPKI bit string")
    if p != len(seq):
        raise ConvertError("SPKI 结构末尾有多余数据")
    if not bits or bits[0] != 0x00:
        raise ConvertError("SPKI 位串未按字节对齐")
    key = bits[1:]
    if len(key) != 32:
        raise ConvertError("SPKI 中 Ed25519 公钥长度应为 32 字节,实际 %d" % len(key))
    return key


def verify_pkcs8(path, expect_pub):
    run_openssl(["pkey", "-in", path, "-noout"])
    der = run_openssl(["pkey", "-in", path, "-pubout", "-outform", "DER"])
    if spki_public_key(der) != expect_pub:
        raise ConvertError(
            "自校验失败:openssl 从转换后的私钥派生的公钥与 OpenSSH 私钥内嵌的公钥不一致")


def verify_spki(path, expect_pub):
    run_openssl(["pkey", "-pubin", "-in", path, "-noout"])
    der = run_openssl(["pkey", "-pubin", "-in", path, "-outform", "DER"])
    if spki_public_key(der) != expect_pub:
        raise ConvertError("自校验失败:openssl 读回的 SPKI 公钥与输入不一致")


def write_atomic(path, text, verify, secret=False):
    """先写临时文件并自校验,通过后才落到目标路径。"""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise ConvertError("输出目录不存在:%s" % directory)
    fd, tmp = tempfile.mkstemp(prefix=".convert-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
        if secret:
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        verify(tmp)
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def convert(input_path, output_path):
    if not os.path.isfile(input_path):
        raise ConvertError("输入文件不存在:%s" % input_path)
    with open(input_path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConvertError("输入不是文本格式的密钥文件")

    if "BEGIN OPENSSH PRIVATE KEY" in text:
        label, der = pem_decode(text)
        if label != "OPENSSH PRIVATE KEY":
            raise ConvertError("PEM 标签是 %s,不是 OPENSSH PRIVATE KEY" % label)
        seed, pub = parse_openssh_private(der)
        write_atomic(output_path, pem_encode("PRIVATE KEY", build_pkcs8(seed)),
                     lambda tmp: verify_pkcs8(tmp, pub), secret=True)
        sys.stdout.write("已写入 %s\n" % output_path)
        sys.stdout.write("自校验通过:openssl pkey 可读,派生公钥与 OpenSSH 私钥内嵌公钥一致\n")
        return

    stripped = text.strip()
    if stripped.startswith("ssh-ed25519"):
        pub = parse_openssh_public(stripped)
        write_atomic(output_path, pem_encode("PUBLIC KEY", build_spki(pub)),
                     lambda tmp: verify_spki(tmp, pub))
        sys.stdout.write("已写入 %s\n" % output_path)
        sys.stdout.write("自校验通过:openssl pkey -pubin 可读,SPKI 公钥与输入一致\n")
        return

    if "BEGIN ENCRYPTED PRIVATE KEY" in text:
        raise ConvertError("输入是带口令的 PKCS#8 私钥,本脚本只做 OpenSSH 到 PEM 的转换")
    if "BEGIN PRIVATE KEY" in text:
        raise ConvertError(
            "输入已经是 OpenSSL PEM 私钥,无需转换;反向转换请用 author_convert_openssl_to_openssh.py")
    if "BEGIN PUBLIC KEY" in text:
        raise ConvertError(
            "输入已经是 OpenSSL PEM 公钥,无需转换;反向转换请用 author_convert_openssl_to_openssh.py")
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN EC PRIVATE KEY" in text:
        raise ConvertError("只支持 Ed25519,输入是 RSA 或 EC 的 PKCS#1、SEC1 私钥")
    for prefix in ("ssh-rsa", "ecdsa-sha2-", "ssh-dss"):
        if stripped.startswith(prefix):
            raise ConvertError("只支持 Ed25519,输入公钥类型是 %s" % prefix)
    raise ConvertError(
        "无法识别的输入格式:只接受 OpenSSH 私钥(-----BEGIN OPENSSH PRIVATE KEY-----)"
        "或 ssh-ed25519 公钥行")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="把 OpenSSH 格式的 Ed25519 密钥转换为 OpenSSL PEM 格式(PKCS#8、SPKI)。")
    parser.add_argument("input", help="输入文件:OpenSSH 私钥或 ssh-ed25519 公钥行")
    parser.add_argument("-o", "--output", help="输出文件,缺省为 <输入文件>.converted")
    force_utf8()
    args = parser.parse_args(argv)

    output_path = args.output or (args.input + ".converted")
    try:
        convert(args.input, output_path)
    except ConvertError as exc:
        sys.stderr.write("错误:%s\n" % exc)
        return 1
    except OSError as exc:
        sys.stderr.write("错误:%s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
