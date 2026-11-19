#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""author_convert_openssl_to_openssh.py

把 OpenSSL PEM 格式的 Ed25519 密钥转换为 OpenSSH 格式。

    私钥  -----BEGIN PRIVATE KEY-----  (PKCS#8)  ->  -----BEGIN OPENSSH PRIVATE KEY-----
    公钥  -----BEGIN PUBLIC KEY-----   (SPKI)    ->  ssh-ed25519 AAAA...  一行

约束:
    只支持 Ed25519;只支持无口令的 PKCS#8 私钥。
    只使用 Python 标准库,不依赖 cryptography 等第三方模块。
    转换后自动自校验(私钥用 ssh-keygen -y 反推公钥比对,公钥用 ssh-keygen -l 校验格式),
    自校验失败则以非零退出码结束。环境里没有 ssh-keygen 时跳过这一步,其余校验照常执行。

用法:
    python author_convert_openssl_to_openssh.py <输入文件> [-o <输出文件>]
"""

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROG = "author_convert_openssl_to_openssh.py"

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


def oid_text(oid):
    """把 OID 内容字节渲染成点分形式,仅用于报错。"""
    if not oid:
        return "<空>"
    values = [oid[0] // 40, oid[0] % 40]
    acc = 0
    for byte in oid[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(acc)
            acc = 0
    return ".".join(str(v) for v in values)


def extract_seed(octets):
    """从 PKCS#8 的 privateKey OCTET STRING 内容里取出 32 字节种子。"""
    if octets and octets[0] == 0x04:
        inner, end = der_read(octets, 0, 0x04, "Ed25519 私钥")
        if end == len(octets) and len(inner) == 32:
            return inner
    if len(octets) == 32:
        return octets
    raise ConvertError("Ed25519 私钥应为嵌套的 32 字节 OCTET STRING,实际长度 %d" % len(octets))


def parse_pkcs8(der):
    """解析无口令的 Ed25519 PrivateKeyInfo,返回 32 字节种子。"""
    seq, end = der_read(der, 0, 0x30, "PKCS#8")
    if end != len(der):
        raise ConvertError("PKCS#8 末尾有多余数据")
    version, p = der_read(seq, 0, 0x02, "PKCS#8 version")
    if version != b"\x00":
        raise ConvertError("PKCS#8 版本不是 0,可能是带口令的 EncryptedPrivateKeyInfo")
    algid, p = der_read(seq, p, 0x30, "PKCS#8 algorithm")
    oid, q = der_read(algid, 0, 0x06, "algorithm oid")
    if oid != OID_ED25519[2:]:
        raise ConvertError("只支持 Ed25519,输入私钥算法是 %s" % oid_text(oid))
    if q != len(algid):
        raise ConvertError("Ed25519 的 AlgorithmIdentifier 不应带参数")
    octets, p = der_read(seq, p, 0x04, "PKCS#8 privateKey")
    if p != len(seq):
        raise ConvertError("PKCS#8 私钥字段后有多余数据")
    return extract_seed(octets)


def spki_public_key(der):
    """从 SPKI DER 中取出 32 字节 Ed25519 公钥。"""
    seq, end = der_read(der, 0, 0x30, "SPKI")
    if end != len(der):
        raise ConvertError("SPKI 末尾有多余数据")
    algid, p = der_read(seq, 0, 0x30, "SPKI algorithm")
    oid, _ = der_read(algid, 0, 0x06, "SPKI algorithm oid")
    if oid != OID_ED25519[2:]:
        raise ConvertError("只支持 Ed25519,输入公钥算法是 %s" % oid_text(oid))
    bits, p = der_read(seq, p, 0x03, "SPKI bit string")
    if p != len(seq):
        raise ConvertError("SPKI 结构末尾有多余数据")
    if not bits or bits[0] != 0x00:
        raise ConvertError("SPKI 位串未按字节对齐")
    key = bits[1:]
    if len(key) != 32:
        raise ConvertError("SPKI 中 Ed25519 公钥长度应为 32 字节,实际 %d" % len(key))
    return key


def parse_openssh_private(der):
    """回读自己写出的 openssh-key-v1 私钥,返回 (seed, pub)。"""
    if not der.startswith(SSH_MAGIC):
        raise ConvertError("不是 openssh-key-v1 结构")
    pos = len(SSH_MAGIC)
    cipher, pos = ssh_read_string(der, pos, "ciphername")
    kdf, pos = ssh_read_string(der, pos, "kdfname")
    kdfopts, pos = ssh_read_string(der, pos, "kdfoptions")
    if cipher != b"none":
        raise ConvertError("自校验失败:写出的私钥 cipher 不是 none")
    if kdf != b"none" or kdfopts:
        raise ConvertError("自校验失败:写出的私钥 kdf 不是 none")
    nkeys = int.from_bytes(der[pos:pos + 4], "big")
    pos += 4
    if nkeys != 1:
        raise ConvertError("自校验失败:写出的私钥密钥数量不是 1")
    pub_outer, pos = ssh_read_string(der, pos, "public key")
    priv_blob, pos = ssh_read_string(der, pos, "private section")
    if pos != len(der):
        raise ConvertError("自校验失败:写出的私钥末尾有多余数据")

    check1 = int.from_bytes(priv_blob[0:4], "big")
    check2 = int.from_bytes(priv_blob[4:8], "big")
    if check1 != check2:
        raise ConvertError("自校验失败:写出的私钥 checkint 两半不一致")
    p = 8
    keytype, p = ssh_read_string(priv_blob, p, "keytype")
    if keytype != SSH_KEYTYPE:
        raise ConvertError("自校验失败:写出的私钥类型不是 ssh-ed25519")
    pub, p = ssh_read_string(priv_blob, p, "public key")
    priv, p = ssh_read_string(priv_blob, p, "private key")
    _comment, p = ssh_read_string(priv_blob, p, "comment")
    if len(priv) != 64 or len(pub) != 32:
        raise ConvertError("自校验失败:写出的私钥长度不符合 Ed25519 约定")
    if priv[32:] != pub:
        raise ConvertError("自校验失败:写出的私钥公钥副本不一致")
    if pub_outer != ssh_string(SSH_KEYTYPE) + ssh_string(pub):
        raise ConvertError("自校验失败:写出的私钥外层公钥不一致")
    pad = priv_blob[p:]
    if pad != bytes(range(1, len(pad) + 1)):
        raise ConvertError("自校验失败:写出的私钥填充字节不符合约定")
    return priv[:32], pub


def parse_openssh_public(text):
    """回读自己写出的一行 ssh-ed25519 公钥,返回 32 字节公钥。"""
    fields = text.split()
    if len(fields) < 2:
        raise ConvertError("自校验失败:写出的 OpenSSH 公钥行格式不正确")
    if fields[0] != "ssh-ed25519":
        raise ConvertError("自校验失败:写出的 OpenSSH 公钥类型不是 ssh-ed25519")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except Exception:
        raise ConvertError("自校验失败:写出的 OpenSSH 公钥主体不是合法的 base64")
    keytype, pos = ssh_read_string(blob, 0, "keytype")
    if keytype != SSH_KEYTYPE:
        raise ConvertError("自校验失败:写出的 OpenSSH 公钥 blob 类型不对")
    pub, pos = ssh_read_string(blob, pos, "public key")
    if pos != len(blob) or len(pub) != 32:
        raise ConvertError("自校验失败:写出的 OpenSSH 公钥 blob 结构不对")
    return pub


def build_openssh_private(seed, pub):
    """按 openssh-key-v1 无口令布局构造私钥 blob,返回 (blob, 公钥 blob)。"""
    check = os.urandom(4)
    body = check + check
    body += ssh_string(SSH_KEYTYPE)
    body += ssh_string(pub)
    body += ssh_string(seed + pub)
    body += ssh_string(b"")
    pad = 8 - (len(body) % 8)
    if pad == 0:
        pad = 8
    body += bytes(range(1, pad + 1))

    pub_blob = ssh_string(SSH_KEYTYPE) + ssh_string(pub)
    out = SSH_MAGIC
    out += ssh_string(b"none")
    out += ssh_string(b"none")
    out += ssh_string(b"")
    out += (1).to_bytes(4, "big")
    out += ssh_string(pub_blob)
    out += ssh_string(body)
    return out, pub_blob


def run_openssl(args):
    exe = shutil.which("openssl")
    if not exe:
        raise ConvertError("找不到 openssl 命令,无法读取 PEM 密钥并做自校验")
    proc = subprocess.run([exe] + list(args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise ConvertError("openssl 执行失败(%s):%s" % (
            " ".join(args), proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout


def ssh_keygen_path():
    return shutil.which("ssh-keygen")


def check_private_with_ssh_keygen(path, expect_pub_blob):
    """返回 ok、missing、skipped-permissions 三种状态;结构性问题直接抛错。"""
    exe = ssh_keygen_path()
    if not exe:
        return "missing"
    proc = subprocess.run([exe, "-y", "-f", path], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", "replace")
        lowered = message.lower()
        if "bad permissions" in lowered or "are too open" in lowered \
                or "unprotected private key" in lowered:
            # 部分环境(例如 Windows 上由脚本新建的文件)会被 ssh-keygen 以权限过宽拒绝,
            # 这与密钥结构无关,记为跳过而不是失败。
            return "skipped-permissions"
        raise ConvertError("自校验失败:ssh-keygen 无法读取转换后的 OpenSSH 私钥:%s"
                           % message.strip())
    fields = proc.stdout.decode("utf-8", "replace").split()
    expect_b64 = base64.b64encode(expect_pub_blob).decode("ascii")
    if len(fields) < 2 or fields[0] != "ssh-ed25519" or fields[1] != expect_b64:
        raise ConvertError(
            "自校验失败:ssh-keygen 从转换后的私钥反推的公钥与 PEM 私钥派生的公钥不一致")
    return "ok"


def check_public_with_ssh_keygen(path):
    """返回 ok 或 missing;格式问题直接抛错。"""
    exe = ssh_keygen_path()
    if not exe:
        return "missing"
    proc = subprocess.run([exe, "-l", "-f", path], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise ConvertError("自校验失败:ssh-keygen -l 无法读取转换后的 OpenSSH 公钥:%s"
                           % proc.stderr.decode("utf-8", "replace").strip())
    return "ok"


def ssh_keygen_suffix(status):
    if status == "ok":
        return ",ssh-keygen -y 反推公钥一致"
    if status == "skipped-permissions":
        return "(ssh-keygen 因文件权限过宽拒绝读取,已跳过该步校验)"
    return "(未找到 ssh-keygen,已跳过该步校验)"


def verify_openssh_private(path, seed, pub):
    with open(path, "rb") as handle:
        _label, der = pem_decode(handle.read().decode("utf-8"))
    got_seed, got_pub = parse_openssh_private(der)
    if got_seed != seed:
        raise ConvertError("自校验失败:转换后私钥的种子与 PKCS#8 私钥不一致")
    if got_pub != pub:
        raise ConvertError("自校验失败:转换后私钥内嵌的公钥与 PEM 派生的公钥不一致")
    return check_private_with_ssh_keygen(path, ssh_string(SSH_KEYTYPE) + ssh_string(pub))


def verify_openssh_public(path, expect_blob):
    with open(path, "rb") as handle:
        got = parse_openssh_public(handle.read().decode("utf-8").strip())
    if ssh_string(SSH_KEYTYPE) + ssh_string(got) != expect_blob:
        raise ConvertError("自校验失败:生成的 OpenSSH 公钥与 PEM 公钥不一致")
    return check_public_with_ssh_keygen(path)


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
        used_ssh_keygen = verify(tmp)
        os.replace(tmp, path)
        tmp = ""
        return used_ssh_keygen
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

    stripped = text.strip()
    if stripped.startswith("ssh-ed25519"):
        raise ConvertError(
            "输入已经是 OpenSSH 公钥,无需转换;反向转换请用 author_convert_openssh_to_openssl.py")
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        raise ConvertError(
            "输入已经是 OpenSSH 私钥,无需转换;反向转换请用 author_convert_openssh_to_openssl.py")
    if "BEGIN ENCRYPTED PRIVATE KEY" in text:
        raise ConvertError(
            "不支持带口令的 PKCS#8 私钥;请先执行 openssl pkey -in <输入文件> -out <新文件> 去掉口令后重试")
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN EC PRIVATE KEY" in text:
        raise ConvertError("只支持 Ed25519,输入是 RSA 或 EC 的 PKCS#1、SEC1 私钥")

    if "BEGIN PRIVATE KEY" in text:
        label, der = pem_decode(text)
        if label != "PRIVATE KEY":
            raise ConvertError("PEM 标签是 %s,不是 PRIVATE KEY" % label)
        seed = parse_pkcs8(der)
        run_openssl(["pkey", "-in", input_path, "-noout"])
        pub = spki_public_key(
            run_openssl(["pkey", "-in", input_path, "-pubout", "-outform", "DER"]))
        blob, _pub_blob = build_openssh_private(seed, pub)
        status = write_atomic(output_path, pem_encode("OPENSSH PRIVATE KEY", blob),
                              lambda tmp: verify_openssh_private(tmp, seed, pub), secret=True)
        sys.stdout.write("已写入 %s\n" % output_path)
        sys.stdout.write("自校验通过:回读结构一致,公钥与 PEM 派生公钥一致%s\n"
                         % ssh_keygen_suffix(status))
        return

    if "BEGIN PUBLIC KEY" in text:
        label, der = pem_decode(text)
        if label != "PUBLIC KEY":
            raise ConvertError("PEM 标签是 %s,不是 PUBLIC KEY" % label)
        pub = spki_public_key(der)
        run_openssl(["pkey", "-pubin", "-in", input_path, "-noout"])
        pub_blob = ssh_string(SSH_KEYTYPE) + ssh_string(pub)
        line = "ssh-ed25519 " + base64.b64encode(pub_blob).decode("ascii") + "\n"
        status = write_atomic(output_path, line,
                              lambda tmp: verify_openssh_public(tmp, pub_blob))
        sys.stdout.write("已写入 %s\n" % output_path)
        if status == "ok":
            sys.stdout.write("自校验通过:ssh-keygen -l 可读,公钥与 PEM 一致\n")
        else:
            sys.stdout.write("自校验通过:公钥与 PEM 一致(未找到 ssh-keygen,跳过其校验)\n")
        return

    raise ConvertError(
        "无法识别的输入格式:只接受 PKCS#8 私钥(-----BEGIN PRIVATE KEY-----)"
        "或 SPKI 公钥(-----BEGIN PUBLIC KEY-----)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="把 OpenSSL PEM 格式的 Ed25519 密钥转换为 OpenSSH 格式(openssh-key-v1、ssh-ed25519)。")
    parser.add_argument("input", help="输入文件:PKCS#8 私钥或 SPKI 公钥")
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
