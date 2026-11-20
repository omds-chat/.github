#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""author_convert_openssl_to_openssh.py

把 OpenSSL PEM 格式的 Ed25519 密钥转换为 OpenSSH 格式。

    私钥  -----BEGIN PRIVATE KEY-----  (PKCS#8)  ->  -----BEGIN OPENSSH PRIVATE KEY-----
    私钥  -----BEGIN ENCRYPTED PRIVATE KEY-----  ->  -----BEGIN OPENSSH PRIVATE KEY-----
    公钥  -----BEGIN PUBLIC KEY-----   (SPKI)    ->  ssh-ed25519 AAAA...  一行

带口令输入(PKCS#8 的 EncryptedPrivateKeyInfo)的处理路径:
    1. 先只解析 PKCS#8 外层的算法字段,取出 PBES2 参数:PBKDF2 的 salt、iterationCount、
       keyLength、伪随机函数,以及分组加密算法与 IV,据此决定解密方式,不靠试解;
    2. 只支持 PBES2 + PBKDF2 + AES-CBC(aes128-cbc、aes192-cbc、aes256-cbc);
       des-ede3-cbc 等其它算法按"不支持"报错,不做猜测式解密;
    3. PBKDF2 走标准库 hashlib.pbkdf2_hmac,AES-CBC 解密由本脚本自带实现;
    4. 解密后按 PEM 结构校验,填充不一致一律按"口令不正确"提示,并写明口令无误则文件可能已损坏。

输出私钥是否带口令由参数决定:
    默认输出不带口令的 openssh-key-v1 私钥,与历史行为一致;
    加 --encrypt-output 后,私有段用 bcrypt_pbkdf 派生密钥、AES-CTR 加密,
    加密算法由 --cipher 指定(默认 aes256-ctr),KDF 轮数由 --rounds 指定(默认 16)。

口令来源(优先级从高到低):
    输入私钥口令:--passphrase 参数 > 环境变量 OPENSSH_KEY_PASSPHRASE > 交互提示;
    输出私钥口令:--output-passphrase 参数 > 环境变量 OPENSSH_OUTPUT_PASSPHRASE > 交互提示
    (交互设置输出口令时要求连续两次输入一致)。

约束:
    只支持 Ed25519。
    只使用 Python 标准库,不依赖 cryptography 等第三方模块。
    转换后自动自校验:回读容器结构并与输入比对;明文私钥还会在环境里有 ssh-keygen 时
    用 ssh-keygen -y 反推公钥比对,公钥用 ssh-keygen -l 校验格式。

退出码:
    0 成功
    1 普通错误:参数、读写、格式无法识别、自校验失败等
    2 口令错误或口令缺失
    3 KDF 或加密参数不支持
    4 不是 Ed25519
    5 私钥结构损坏

用法:
    python author_convert_openssl_to_openssh.py <输入文件> [-o <输出文件>]
    python author_convert_openssl_to_openssh.py author_secret -o id_ed25519
    python author_convert_openssl_to_openssh.py author_secret.pub -o id_ed25519.pub
    python author_convert_openssl_to_openssh.py author_secret -o id_ed25519 --encrypt-output
    OPENSSH_KEY_PASSPHRASE=... python author_convert_openssl_to_openssh.py author_secret -o id_ed25519
"""

import argparse
import base64
import getpass
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROG = "author_convert_openssl_to_openssh.py"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PASSPHRASE = 2
EXIT_KDF = 3
EXIT_KEYTYPE = 4
EXIT_CORRUPT = 5

PASSPHRASE_ENV = "OPENSSH_KEY_PASSPHRASE"
OUTPUT_PASSPHRASE_ENV = "OPENSSH_OUTPUT_PASSPHRASE"
PROMPT_ATTEMPTS = 3

SSH_MAGIC = b"openssh-key-v1\x00"
SSH_KEYTYPE = b"ssh-ed25519"
OID_ED25519 = b"\x06\x03\x2b\x65\x70"
PEM_RE = re.compile(r"-----BEGIN ([A-Za-z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)

AES_BLOCK = 16
# ciphername -> 密钥字节数。这三种都是 CTR 模式,密文与明文等长,不需要去填充。
CTR_CIPHERS = {"aes128-ctr": 16, "aes192-ctr": 24, "aes256-ctr": 32}
DEFAULT_CIPHER = "aes256-ctr"
DEFAULT_ROUNDS = 16
# 输出带口令私钥时 bcrypt_pbkdf 用的 salt 长度,与 ssh-keygen 一致
KDF_SALT_BYTES = 16

# PKCS#8 口令加密(PBES2)用到的 OID
OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_DES_EDE3_CBC = "1.2.840.113549.3.7"
PRF_OIDS = {
    "1.2.840.113549.2.7": "sha1",
    "1.2.840.113549.2.8": "sha224",
    "1.2.840.113549.2.9": "sha256",
    "1.2.840.113549.2.10": "sha384",
    "1.2.840.113549.2.11": "sha512",
}
# OID -> (算法名, 密钥字节数),只收 AES-CBC 三档
CBC_CIPHERS = {
    "2.16.840.1.101.3.4.1.2": ("aes128-cbc", 16),
    "2.16.840.1.101.3.4.1.22": ("aes192-cbc", 24),
    "2.16.840.1.101.3.4.1.42": ("aes256-cbc", 32),
}


class ConvertError(Exception):
    """转换或自校验失败。"""

    exit_code = EXIT_ERROR


class PassphraseError(ConvertError):
    """口令错误、口令缺失,或口令为空。"""

    exit_code = EXIT_PASSPHRASE


class KdfUnsupportedError(ConvertError):
    """KDF 或加密参数不在本脚本支持的范围内。"""

    exit_code = EXIT_KDF


class UnsupportedKeyTypeError(ConvertError):
    """密钥不是 Ed25519。"""

    exit_code = EXIT_KEYTYPE


class CorruptKeyError(ConvertError):
    """私钥结构损坏或被篡改。"""

    exit_code = EXIT_CORRUPT


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


def ssh_read_string(buf, pos, what, error=ConvertError):
    """读 openssh 的 uint32 长度前缀字符串。"""
    if pos + 4 > len(buf):
        raise error("OpenSSH 结构被截断:%s" % what)
    n = int.from_bytes(buf[pos:pos + 4], "big")
    pos += 4
    if n > len(buf) - pos:
        raise error("OpenSSH 字符串长度越界:%s" % what)
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


# ---------------------------------------------------------------------------
# Blowfish:bcrypt_pbkdf 的地基,只用到 bcrypt 需要的部分
#
# 初始 P 数组与 S 盒就是圆周率十六进制小数的前 1042 个 32 位字,这里直接写成
# 常量,方便与 OpenSSH 自带的 blowfish.c 逐字对照。状态用一个长度 1042 的列表
# 表示:前 18 个字是 P,后 1024 个字是 S(四个 256 字子盒依次拼接)。
# ---------------------------------------------------------------------------

_BLOWFISH_HEX = """
243F6A88 85A308D3 13198A2E 03707344 A4093822 299F31D0 082EFA98 EC4E6C89
452821E6 38D01377 BE5466CF 34E90C6C C0AC29B7 C97C50DD 3F84D5B5 B5470917
9216D5D9 8979FB1B D1310BA6 98DFB5AC 2FFD72DB D01ADFB7 B8E1AFED 6A267E96
BA7C9045 F12C7F99 24A19947 B3916CF7 0801F2E2 858EFC16 636920D8 71574E69
A458FEA3 F4933D7E 0D95748F 728EB658 718BCD58 82154AEE 7B54A41D C25A59B5
9C30D539 2AF26013 C5D1B023 286085F0 CA417918 B8DB38EF 8E79DCB0 603A180E
6C9E0E8B B01E8A3E D71577C1 BD314B27 78AF2FDA 55605C60 E65525F3 AA55AB94
57489862 63E81440 55CA396A 2AAB10B6 B4CC5C34 1141E8CE A15486AF 7C72E993
B3EE1411 636FBC2A 2BA9C55D 741831F6 CE5C3E16 9B87931E AFD6BA33 6C24CF5C
7A325381 28958677 3B8F4898 6B4BB9AF C4BFE81B 66282193 61D809CC FB21A991
487CAC60 5DEC8032 EF845D5D E98575B1 DC262302 EB651B88 23893E81 D396ACC5
0F6D6FF3 83F44239 2E0B4482 A4842004 69C8F04A 9E1F9B5E 21C66842 F6E96C9A
670C9C61 ABD388F0 6A51A0D2 D8542F68 960FA728 AB5133A3 6EEF0B6C 137A3BE4
BA3BF050 7EFB2A98 A1F1651D 39AF0176 66CA593E 82430E88 8CEE8619 456F9FB4
7D84A5C3 3B8B5EBE E06F75D8 85C12073 401A449F 56C16AA6 4ED3AA62 363F7706
1BFEDF72 429B023D 37D0D724 D00A1248 DB0FEAD3 49F1C09B 075372C9 80991B7B
25D479D8 F6E8DEF7 E3FE501A B6794C3B 976CE0BD 04C006BA C1A94FB6 409F60C4
5E5C9EC2 196A2463 68FB6FAF 3E6C53B5 1339B2EB 3B52EC6F 6DFC511F 9B30952C
CC814544 AF5EBD09 BEE3D004 DE334AFD 660F2807 192E4BB3 C0CBA857 45C8740F
D20B5F39 B9D3FBDB 5579C0BD 1A60320A D6A100C6 402C7279 679F25FE FB1FA3CC
8EA5E9F8 DB3222F8 3C7516DF FD616B15 2F501EC8 AD0552AB 323DB5FA FD238760
53317B48 3E00DF82 9E5C57BB CA6F8CA0 1A87562E DF1769DB D542A8F6 287EFFC3
AC6732C6 8C4F5573 695B27B0 BBCA58C8 E1FFA35D B8F011A0 10FA3D98 FD2183B8
4AFCB56C 2DD1D35B 9A53E479 B6F84565 D28E49BC 4BFB9790 E1DDF2DA A4CB7E33
62FB1341 CEE4C6E8 EF20CADA 36774C01 D07E9EFE 2BF11FB4 95DBDA4D AE909198
EAAD8E71 6B93D5A0 D08ED1D0 AFC725E0 8E3C5B2F 8E7594B7 8FF6E2FB F2122B64
8888B812 900DF01C 4FAD5EA0 688FC31C D1CFF191 B3A8C1AD 2F2F2218 BE0E1777
EA752DFE 8B021FA1 E5A0CC0F B56F74E8 18ACF3D6 CE89E299 B4A84FE0 FD13E0B7
7CC43B81 D2ADA8D9 165FA266 80957705 93CC7314 211A1477 E6AD2065 77B5FA86
C75442F5 FB9D35CF EBCDAF0C 7B3E89A0 D6411BD3 AE1E7E49 00250E2D 2071B35E
226800BB 57B8E0AF 2464369B F009B91E 5563911D 59DFA6AA 78C14389 D95A537F
207D5BA2 02E5B9C5 83260376 6295CFA9 11C81968 4E734A41 B3472DCA 7B14A94A
1B510052 9A532915 D60F573F BC9BC6E4 2B60A476 81E67400 08BA6FB5 571BE91F
F296EC6B 2A0DD915 B6636521 E7B9F9B6 FF34052E C5855664 53B02D5D A99F8FA1
08BA4799 6E85076A 4B7A70E9 B5B32944 DB75092E C4192623 AD6EA6B0 49A7DF7D
9CEE60B8 8FEDB266 ECAA8C71 699A17FF 5664526C C2B19EE1 193602A5 75094C29
A0591340 E4183A3E 3F54989A 5B429D65 6B8FE4D6 99F73FD6 A1D29C07 EFE830F5
4D2D38E6 F0255DC1 4CDD2086 8470EB26 6382E9C6 021ECC5E 09686B3F 3EBAEFC9
3C971814 6B6A70A1 687F3584 52A0E286 B79C5305 AA500737 3E07841C 7FDEAE5C
8E7D44EC 5716F2B8 B03ADA37 F0500C0D F01C1F04 0200B3FF AE0CF51A 3CB574B2
25837A58 DC0921BD D19113F9 7CA92FF6 94324773 22F54701 3AE5E581 37C2DADC
C8B57634 9AF3DDA7 A9446146 0FD0030E ECC8C73E A4751E41 E238CD99 3BEA0E2F
3280BBA1 183EB331 4E548B38 4F6DB908 6F420D03 F60A04BF 2CB81290 24977C79
5679B072 BCAF89AF DE9A771F D9930810 B38BAE12 DCCF3F2E 5512721F 2E6B7124
501ADDE6 9F84CD87 7A584718 7408DA17 BC9F9ABC E94B7D8C EC7AEC3A DB851DFA
63094366 C464C3D2 EF1C1847 3215D908 DD433B37 24C2BA16 12A14D43 2A65C451
50940002 133AE4DD 71DFF89E 10314E55 81AC77D6 5F11199B 043556F1 D7A3C76B
3C11183B 5924A509 F28FE6ED 97F1FBFA 9EBABF2C 1E153C6E 86E34570 EAE96FB1
860E5E0A 5A3E2AB3 771FE71C 4E3D06FA 2965DCB9 99E71D0F 803E89D6 5266C825
2E4CC978 9C10B36A C6150EBA 94E2EA78 A5FC3C53 1E0A2DF4 F2F74EA7 361D2B3D
1939260F 19C27960 5223A708 F71312B6 EBADFE6E EAC31F66 E3BC4595 A67BC883
B17F37D1 018CFF28 C332DDEF BE6C5AA5 65582185 68AB9802 EECEA50F DB2F953B
2AEF7DAD 5B6E2F84 1521B628 29076170 ECDD4775 619F1510 13CCA830 EB61BD96
0334FE1E AA0363CF B5735C90 4C70A239 D59E9E0B CBAADE14 EECC86BC 60622CA7
9CAB5CAB B2F3846E 648B1EAF 19BDF0CA A02369B9 655ABB50 40685A32 3C2AB4B3
319EE9D5 C021B8F7 9B540B19 875FA099 95F7997E 623D7DA8 F837889A 97E32D77
11ED935F 16681281 0E358829 C7E61FD6 96DEDFA1 7858BA99 57F584A5 1B227263
9B83C3FF 1AC24696 CDB30AEB 532E3054 8FD948E4 6DBC3128 58EBF2EF 34C6FFEA
FE28ED61 EE7C3C73 5D4A14D9 E864B7E3 42105D14 203E13E0 45EEE2B6 A3AAABEA
DB6C4F15 FACB4FD0 C742F442 EF6ABBB5 654F3B1D 41CD2105 D81E799E 86854DC7
E44B476A 3D816250 CF62A1F2 5B8D2646 FC8883A0 C1C7B6A3 7F1524C3 69CB7492
47848A0B 5692B285 095BBF00 AD19489D 1462B174 23820E00 58428D2A 0C55F5EA
1DADF43E 233F7061 3372F092 8D937E41 D65FECF1 6C223BDB 7CDE3759 CBEE7460
4085F2A7 CE77326E A6078084 19F8509E E8EFD855 61D99735 A969A7AA C50C06C2
5A04ABFC 800BCADC 9E447A2E C3453484 FDD56705 0E1E9EC9 DB73DBD3 105588CD
675FDA79 E3674340 C5C43465 713E38D8 3D28F89E F16DFF20 153E21E7 8FB03D4A
E6E39F2B DB83ADF7 E93D5A68 948140F7 F64C261C 94692934 411520F7 7602D4F7
BCF46B2E D4A20068 D4082471 3320F46A 43B7D4B7 500061AF 1E39F62E 97244546
14214F74 BF8B8840 4D95FC1D 96B591AF 70F4DDD3 66A02F45 BFBC09EC 03BD9785
7FAC6DD0 31CB8504 96EB27B3 55FD3941 DA2547E6 ABCA0A9A 28507825 530429F4
0A2C86DA E9B66DFB 68DC1462 D7486900 680EC0A4 27A18DEE 4F3FFEA2 E887AD8C
B58CE006 7AF4D6B6 AACE1E7C D3375FEC CE78A399 406B2A42 20FE9E35 D9F385B9
EE39D7AB 3B124E8B 1DC9FAF7 4B6D1856 26A36631 EAE397B2 3A6EFA74 DD5B4332
6841E7F7 CA7820FB FB0AF54E D8FEB397 454056AC BA489527 55533A3A 20838D87
FE6BA9B7 D096954B 55A867BC A1159A58 CCA92963 99E1DB33 A62A4A56 3F3125F9
5EF47E1C 9029317C FDF8E802 04272F70 80BB155C 05282CE3 95C11548 E4C66D22
48C1133F C70F86DC 07F9C9EE 41041F0F 404779A4 5D886E17 325F51EB D59BC0D1
F2BCC18F 41113564 257B7834 602A9C60 DFF8E8A3 1F636C1B 0E12B4C2 02E1329E
AF664FD1 CAD18115 6B2395E0 333E92E1 3B240B62 EEBEB922 85B2A20E E6BA0D99
DE720C8C 2DA2F728 D0127845 95B794FD 647D0862 E7CCF5F0 5449A36F 877D48FA
C39DFD27 F33E8D1E 0A476341 992EFF74 3A6F6EAB F4F8FD37 A812DC60 A1EBDDF8
991BE14C DB6E6B0D C67B5510 6D672C37 2765D43B DCD0E804 F1290DC7 CC00FFA3
B5390F92 690FED0B 667B9FFB CEDB7D9C A091CF0B D9155EA3 BB132F88 515BAD24
7B9479BF 763BD6EB 37392EB3 CC115979 8026E297 F42E312D 6842ADA7 C66A2B3B
12754CCC 782EF11C 6A124237 B79251E7 06A1BBE6 4BFB6350 1A6B1018 11CAEDFA
3D25BDD8 E2E1C3C9 44421659 0A121386 D90CEC6E D5ABEA2A 64AF674E DA86A85F
BEBFE988 64E4C3FE 9DBC8057 F0F7C086 60787BF8 6003604D D1FD8346 F6381FB0
7745AE04 D736FCCC 83426B33 F01EAB71 B0804187 3C005E5F 77A057BE BDE8AE24
55464299 BF582E61 4E58F48F F2DDFDA2 F474EF38 8789BDC2 5366F9C3 C8B38E74
B475F255 46FCD9B9 7AEB2661 8B1DDF84 846A0E79 915F95E2 466E598E 20B45770
8CD55591 C902DE4C B90BACE1 BB8205D0 11A86248 7574A99E B77F19B6 E0A9DC09
662D09A1 C4324633 E85A1F02 09F0BE8C 4A99A025 1D6EFE10 1AB93D1D 0BA5A4DF
A186F20F 2868F169 DCB7DA83 573906FE A1E2CE9B 4FCD7F52 50115E01 A70683FA
A002B5C4 0DE6D027 9AF88C27 773F8641 C3604C06 61A806B5 F0177A28 C0F586E0
006058AA 30DC7D62 11E69ED7 2338EA63 53C2DD94 C2C21634 BBCBEE56 90BCB6DE
EBFC7DA1 CE591D76 6F05E409 4B7C0188 39720A3D 7C927C24 86E3725F 724D9DB9
1AC15BB4 D39EB8FC ED545578 08FCA5B5 D83D7CD3 4DAD0FC4 1E50EF5E B161E6F8
A28514D9 6C51133C 6FD5C7E7 56E14EC4 362ABFCE DDC6C837 D79A3234 92638212
670EFA8E 406000E0 3A39CE37 D3FAF5CF ABC27737 5AC52D1B 5CB0679E 4FA33742
D3822740 99BC9BBE D5118E9D BF0F7315 D62D1C7E C700C47B B78C1B6B 21A19045
B26EB1BE 6A366EB4 5748AB2F BC946E79 C6A376D2 6549C2C8 530FF8EE 468DDE7D
D5730A1D 4CD04DC6 2939BBDB A9BA4650 AC9526E8 BE5EE304 A1FAD5F0 6A2D519A
63EF8CE2 9A86EE22 C089C2B8 43242EF6 A51E03AA 9CF2D0A4 83C061BA 9BE96A4D
8FE51550 BA645BD6 2826A2F9 A73A3AE1 4BA99586 EF5562E9 C72FEFD3 F752F7DA
3F046F69 77FA0A59 80E4A915 87B08601 9B09E6AD 3B3EE593 E990FD5A 9E34D797
2CF0B7D9 022B8B51 96D5AC3A 017DA67D D1CF3ED6 7C7D2D28 1F9F25CF ADF2B89B
5AD6B472 5A88F54C E029AC71 E019A5E6 47B0ACFD ED93FA9B E8D3C48D 283B57CC
F8D56629 79132E28 785F0191 ED756055 F7960E44 E3D35E8C 15056DD4 88F46DBA
03A16125 0564F0BD C3EB9E15 3C9057A2 97271AEC A93A072A 1B3F6D9B 1E6321F5
F59C66FB 26DCF319 7533D928 B155FDF5 03563482 8ABA3CBB 28517711 C20AD9F8
ABCC5167 CCAD925F 4DE81751 3830DC8E 379D5862 9320F991 EA7A90C2 FB3E7BCE
5121CE64 774FBE32 A8B6E37E C3293D46 48DE5369 6413E680 A2AE0810 DD6DB224
69852DFD 09072166 B39A460A 6445C0DD 586CDECF 1C20C8AE 5BBEF7DD 1B588D40
CCD2017F 6BB4E3BB DDA26A7E 3A59FF45 3E350A44 BCB4CDD5 72EACEA8 FA6484BB
8D6612AE BF3C6F47 D29BE463 542F5D9E AEC2771B F64E6370 740E0D8D E75B1357
F8721671 AF537D5D 4040CB08 4EB4E2CC 34D2466A 0115AF84 E1B00428 95983A1D
06B89FB4 CE6EA048 6F3F3B82 3520AB82 011A1D4B 277227F8 611560B1 E7933FDC
BB3A792B 344525BD A08839E1 51CE794B 2F32C9B7 A01FBAC9 E01CC87E BCC7D1F6
CF0111C3 A1E8AAC7 1A908749 D44FBD9A D0DADECB D50ADA38 0339C32A C6913667
8DF9317C E0B12B4F F79E59B7 43F5BB3A F2D519FF 27D9459C BF97222C 15E6FC2A
0F91FC71 9B941525 FAE59361 CEB69CEB C2A86459 12BAA8D1 B6C1075E E3056A0C
10D25065 CB03A442 E0EC6E0E 1698DB3B 4C98A0BE 3278E964 9F1F9532 E0D392DF
D3A0342B 8971F21E 1B0A7441 4BA3348C C5BE7120 C37632D8 DF359F8D 9B992F2E
E60B6F47 0FE3F11D E54CDA54 1EDAD891 CE6279CF CD3E7E6F 1618B166 FD2C1D05
848FD2C5 F6FB2299 F523F357 A6327623 93A83531 56CCCD02 ACF08162 5A75EBB5
6E163697 88D273CC DE966292 81B949D0 4C50901B 71C65614 E6C6C7BD 327A140A
45E1D006 C3F27B9A C9AA53FD 62A80F00 BB25BFE2 35BDD2F6 71126905 B2040222
B6CBCF7C CD769C2B 53113EC0 1640E3D3 38ABBD60 2547ADF0 BA38209C F746CE76
77AFA1C5 20756060 85CBFE4E 8AE88DD8 7AAAF9B0 4CF9AA7E 1948C25C 02FB8A8C
01C36AE4 D6EBE1F9 90D4F869 A65CDEA0 3F09252D C208E69F B74E6132 CE77E25B
578FDFE3 3AC372E6
"""

BF_P_WORDS = 18
BF_S_WORDS = 1024
BF_STATE_WORDS = BF_P_WORDS + BF_S_WORDS
BF_INIT_STATE = [int(word, 16) for word in _BLOWFISH_HEX.split()]
if len(BF_INIT_STATE) != BF_STATE_WORDS:
    raise ConvertError("内置 Blowfish 常量数量不对:期望 %d 个字,实际 %d 个"
                       % (BF_STATE_WORDS, len(BF_INIT_STATE)))

# S 的四个子盒在状态列表中的起始位置:18 + 256 * i
BF_S0 = BF_P_WORDS
BF_S1 = BF_P_WORDS + 256
BF_S2 = BF_P_WORDS + 512
BF_S3 = BF_P_WORDS + 768
BF_MASK = 0xFFFFFFFF


def bf_encipher(state, xl, xr):
    """加密一对 32 位字,与 OpenSSH 的 Blowfish_encipher 等价。

    16 轮按两轮一组展开,省掉每组末尾的交换;C 语言用 uint32 自然回绕,
    Python 的整数不会溢出,所以每次 F 运算后都要 & BF_MASK。
    """
    s0, s1, s2, s3 = BF_S0, BF_S1, BF_S2, BF_S3  # 局部变量比全局查找快得多
    mask = BF_MASK
    for i in range(0, 16, 2):
        xl ^= state[i]
        xr = (((((state[s0 + (xl >> 24)] + state[s1 + ((xl >> 16) & 0xFF)]) & mask)
                ^ state[s2 + ((xl >> 8) & 0xFF)]) + state[s3 + (xl & 0xFF)]) ^ xr) & mask
        xr ^= state[i + 1]
        xl = (((((state[s0 + (xr >> 24)] + state[s1 + ((xr >> 16) & 0xFF)]) & mask)
                ^ state[s2 + ((xr >> 8) & 0xFF)]) + state[s3 + (xr & 0xFF)]) ^ xl) & mask
    # 两轮一组的写法让变量角色回到起点;C 里 16 轮交换之后还有一次撤销交换,
    # 所以最后两把 P 要按交换后的位置异或回去
    return xr ^ state[17], xl ^ state[16]


def bf_stream2word(data, pos):
    """从 data 中循环取 4 字节组成一个 32 位字,返回 (字, 新位置)。"""
    n = len(data)
    word = 0
    for _ in range(4):
        word = (word << 8) | data[pos]
        pos += 1
        if pos >= n:
            pos = 0
    return word, pos


def bf_expand0state(state, key):
    """Blowfish_expand0state:P 与 S 用 key 重新初始化,再原地迭代加密。"""
    pos = 0
    for i in range(BF_P_WORDS):
        word, pos = bf_stream2word(key, pos)
        state[i] ^= word
    left = right = 0
    for i in range(0, BF_P_WORDS, 2):
        left, right = bf_encipher(state, left, right)
        state[i] = left
        state[i + 1] = right
    for i in range(0, BF_S_WORDS, 2):
        left, right = bf_encipher(state, left, right)
        state[BF_P_WORDS + i] = left
        state[BF_P_WORDS + i + 1] = right


def bf_expandstate(state, data, key):
    """Blowfish_expandstate:除 key 之外,再用 data(salt)异或进迭代输入。"""
    pos = 0
    for i in range(BF_P_WORDS):
        word, pos = bf_stream2word(key, pos)
        state[i] ^= word
    pos = 0
    left = right = 0
    for i in range(0, BF_P_WORDS, 2):
        word, pos = bf_stream2word(data, pos)
        left ^= word
        word, pos = bf_stream2word(data, pos)
        right ^= word
        left, right = bf_encipher(state, left, right)
        state[i] = left
        state[i + 1] = right
    for i in range(0, BF_S_WORDS, 2):
        word, pos = bf_stream2word(data, pos)
        left ^= word
        word, pos = bf_stream2word(data, pos)
        right ^= word
        left, right = bf_encipher(state, left, right)
        state[BF_P_WORDS + i] = left
        state[BF_P_WORDS + i + 1] = right


# bcrypt 的固定口令常量,32 字节,正好 8 个 32 位字
BCRYPT_MAGIC = b"OxychromaticBlowfishSwatDynamite"
BCRYPT_WORDS = 8
BCRYPT_HASH_BYTES = BCRYPT_WORDS * 4


def bcrypt_hash(sha2pass, sha2salt):
    """OpenBSD bcrypt_hash():输入两段 64 字节摘要,输出 32 字节。"""
    state = list(BF_INIT_STATE)
    bf_expandstate(state, sha2salt, sha2pass)
    for _ in range(64):
        bf_expand0state(state, sha2salt)
        bf_expand0state(state, sha2pass)

    pos = 0
    words = []
    for _ in range(BCRYPT_WORDS):
        word, pos = bf_stream2word(BCRYPT_MAGIC, pos)
        words.append(word)
    for _ in range(64):
        for i in range(0, BCRYPT_WORDS, 2):
            words[i], words[i + 1] = bf_encipher(state, words[i], words[i + 1])

    out = bytearray(BCRYPT_HASH_BYTES)
    for i, word in enumerate(words):
        # OpenSSH/blowfish 按小端把 32 位字写回字节
        out[4 * i:4 * i + 4] = word.to_bytes(4, "little")
    return bytes(out)


def bcrypt_pbkdf(passphrase, salt, keylen, rounds):
    """OpenBSD bcrypt_pbkdf():用口令与 salt 派生 keylen 字节。"""
    if keylen < 1:
        raise KdfUnsupportedError("要求的密钥长度为 %d,无效" % keylen)
    if rounds < 1:
        raise KdfUnsupportedError("bcrypt_pbkdf 的 rounds 为 %d,无效" % rounds)
    sha2pass = hashlib.sha512(passphrase).digest()
    stride = (keylen + BCRYPT_HASH_BYTES - 1) // BCRYPT_HASH_BYTES
    amount = (keylen + stride - 1) // stride
    out = bytearray(keylen)
    remaining = keylen
    count = 1
    while remaining > 0:
        sha2salt = hashlib.sha512(salt + count.to_bytes(4, "big")).digest()
        tmp = bcrypt_hash(sha2pass, sha2salt)
        block = bytearray(tmp)
        for _ in range(1, rounds):
            # 后续每一轮都拿"上一次 bcrypt_hash 的输出"当 salt,异或结果只进累加器
            sha2salt = hashlib.sha512(tmp).digest()
            tmp = bcrypt_hash(sha2pass, sha2salt)
            for j in range(BCRYPT_HASH_BYTES):
                block[j] ^= tmp[j]
        written = 0
        for i in range(min(amount, remaining)):
            dest = i * stride + (count - 1)
            if dest >= keylen:
                break
            out[dest] = block[i]
            written = i + 1
        if not written:
            break
        remaining -= written
        count += 1
    return bytes(out)

# ---------------------------------------------------------------------------
# AES-CTR:加密与解密是同一条路,CTR 模式下二者是同一个操作
# ---------------------------------------------------------------------------

_AES_SBOX_HEX = """
637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0
b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275
09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf
d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2
cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb
e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08
ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e
e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16
"""
AES_SBOX = bytes.fromhex("".join(_AES_SBOX_HEX.split()))
if len(AES_SBOX) != 256:
    raise ConvertError("内置 AES S 盒长度不对:期望 256 字节,实际 %d" % len(AES_SBOX))

# ShiftRows 的置换表:新状态第 i 字节取自旧状态第 _AES_SHIFT[i] 字节
_AES_SHIFT = tuple(
    (i % 4) + 4 * (((i // 4) + (i % 4)) % 4) for i in range(AES_BLOCK))


def aes_xtime(byte):
    """GF(2^8) 上乘以 2。"""
    byte <<= 1
    if byte & 0x100:
        byte ^= 0x11B
    return byte & 0xFF


def aes_sub_word(word):
    """对一个 32 位字做 SubWord。"""
    return ((AES_SBOX[(word >> 24) & 0xFF] << 24)
            | (AES_SBOX[(word >> 16) & 0xFF] << 16)
            | (AES_SBOX[(word >> 8) & 0xFF] << 8)
            | AES_SBOX[word & 0xFF])


def aes_expand_key(key):
    """AES 密钥扩展,返回 (轮密钥字列表, 轮数);支持 128/192/256 位密钥。"""
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise KdfUnsupportedError("AES 密钥长度 %d 字节不受支持" % len(key))
    rounds = nk + 6
    words = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = words[i - 1]
        if i % nk == 0:
            temp = (((temp << 8) | (temp >> 24)) & 0xFFFFFFFF)  # RotWord
            temp = aes_sub_word(temp) ^ (rcon << 24)
            rcon = aes_xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = aes_sub_word(temp)
        words.append(words[i - nk] ^ temp)
    return words, rounds


def aes_add_round_key(state, words, rnd):
    for column in range(4):
        word = words[4 * rnd + column]
        base = 4 * column
        for row in range(4):
            state[base + row] ^= (word >> (24 - 8 * row)) & 0xFF


def aes_mix_columns(state):
    for column in range(4):
        base = 4 * column
        a0, a1, a2, a3 = state[base:base + 4]
        state[base] = aes_xtime(a0) ^ (aes_xtime(a1) ^ a1) ^ a2 ^ a3
        state[base + 1] = a0 ^ aes_xtime(a1) ^ (aes_xtime(a2) ^ a2) ^ a3
        state[base + 2] = a0 ^ a1 ^ aes_xtime(a2) ^ (aes_xtime(a3) ^ a3)
        state[base + 3] = (aes_xtime(a0) ^ a0) ^ a1 ^ a2 ^ aes_xtime(a3)


def aes_encrypt_block(key_words, rounds, block):
    """加密一个 16 字节分组,状态按列优先存放。"""
    state = list(block)
    aes_add_round_key(state, key_words, 0)
    for rnd in range(1, rounds):
        state = [AES_SBOX[byte] for byte in state]
        state = [state[_AES_SHIFT[i]] for i in range(AES_BLOCK)]
        aes_mix_columns(state)
        aes_add_round_key(state, key_words, rnd)
    state = [AES_SBOX[byte] for byte in state]
    state = [state[_AES_SHIFT[i]] for i in range(AES_BLOCK)]
    aes_add_round_key(state, key_words, rounds)
    return bytes(state)


def aes_ctr_crypt(key, iv, data):
    """AES-CTR:计数器 16 字节按大端递增,加密与解密是同一个操作。"""
    key_words, rounds = aes_expand_key(key)
    out = bytearray(data)
    counter = int.from_bytes(iv, "big")
    for offset in range(0, len(data), AES_BLOCK):
        keystream = aes_encrypt_block(key_words, rounds, counter.to_bytes(AES_BLOCK, "big"))
        end = min(offset + AES_BLOCK, len(data))
        for i in range(offset, end):
            out[i] ^= keystream[i - offset]
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)

# ---------------------------------------------------------------------------
# AES-CBC 解密:读 PKCS#8 的 PBES2 口令加密私钥要用到反方向
# ---------------------------------------------------------------------------

def aes_gf_mul(a, b):
    """GF(2^8) 上两个字节相乘,供 InvMixColumns 使用。"""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return product


def _build_inv_sbox():
    table = bytearray(256)
    for index, value in enumerate(AES_SBOX):
        table[value] = index
    return bytes(table)


AES_INV_SBOX = _build_inv_sbox()

# InvShiftRows 的置换表:新状态第 i 字节取自旧状态第 _AES_INV_SHIFT[i] 字节
_AES_INV_SHIFT = tuple(
    (i % 4) + 4 * (((i // 4) - (i % 4)) % 4) for i in range(AES_BLOCK))


def aes_inv_shift_rows(state):
    return [state[_AES_INV_SHIFT[i]] for i in range(AES_BLOCK)]


def aes_inv_sub_bytes(state):
    return [AES_INV_SBOX[byte] for byte in state]


def aes_inv_mix_columns(state):
    for column in range(4):
        base = 4 * column
        a0, a1, a2, a3 = state[base:base + 4]
        state[base] = (aes_gf_mul(a0, 14) ^ aes_gf_mul(a1, 11)
                       ^ aes_gf_mul(a2, 13) ^ aes_gf_mul(a3, 9))
        state[base + 1] = (aes_gf_mul(a0, 9) ^ aes_gf_mul(a1, 14)
                           ^ aes_gf_mul(a2, 11) ^ aes_gf_mul(a3, 13))
        state[base + 2] = (aes_gf_mul(a0, 13) ^ aes_gf_mul(a1, 9)
                           ^ aes_gf_mul(a2, 14) ^ aes_gf_mul(a3, 11))
        state[base + 3] = (aes_gf_mul(a0, 11) ^ aes_gf_mul(a1, 13)
                           ^ aes_gf_mul(a2, 9) ^ aes_gf_mul(a3, 14))


def aes_decrypt_block(key_words, rounds, block):
    """解密一个 16 字节分组,状态布局与 aes_encrypt_block 相同。"""
    state = list(block)
    aes_add_round_key(state, key_words, rounds)
    for rnd in range(rounds - 1, 0, -1):
        state = aes_inv_shift_rows(state)
        state = aes_inv_sub_bytes(state)
        aes_add_round_key(state, key_words, rnd)
        aes_inv_mix_columns(state)
    state = aes_inv_shift_rows(state)
    state = aes_inv_sub_bytes(state)
    aes_add_round_key(state, key_words, 0)
    return bytes(state)


def aes_cbc_decrypt(key, iv, data):
    """AES-CBC 解密,只用于读 PKCS#8 的口令加密私钥。"""
    if len(iv) != AES_BLOCK:
        raise KdfUnsupportedError("AES-CBC 的 IV 长度是 %d 字节,应为 %d" % (len(iv), AES_BLOCK))
    if not data or len(data) % AES_BLOCK:
        raise CorruptKeyError("加密数据长 %d 字节,不是 %d 的整数倍" % (len(data), AES_BLOCK))
    key_words, rounds = aes_expand_key(key)
    out = bytearray()
    previous = iv
    for offset in range(0, len(data), AES_BLOCK):
        chunk = data[offset:offset + AES_BLOCK]
        plain = aes_decrypt_block(key_words, rounds, chunk)
        out.extend(a ^ b for a, b in zip(plain, previous))
        previous = chunk
    return bytes(out)


def strip_pkcs7(data, block):
    """去掉 PKCS#7 填充;填充不合法按口令错误处理。"""
    if not data or len(data) % block:
        raise PassphraseError("解密后长度不是 %d 的整数倍,口令可能不正确" % block)
    pad = data[-1]
    if pad < 1 or pad > block:
        raise PassphraseError(
            "解密后填充长度 %d 非法,口令可能不正确;口令无误则私钥可能已损坏" % pad)
    if data[-pad:] != bytes([pad]) * pad:
        raise PassphraseError(
            "解密后填充字节不一致,口令可能不正确;口令无误则私钥可能已损坏")
    return data[:-pad]


# ---------------------------------------------------------------------------
# PKCS#8 的 EncryptedPrivateKeyInfo:只读不写
# ---------------------------------------------------------------------------

def parse_pbkdf2_params(der):
    """PBKDF2-params:OCTET STRING salt、INTEGER iterationCount、可选 keyLength 与 prf。"""
    salt, pos = der_read(der, 0, 0x04, "PBKDF2 salt")
    raw, pos = der_read(der, pos, 0x02, "PBKDF2 iterationCount")
    rounds = int.from_bytes(raw, "big")
    if rounds < 1:
        raise KdfUnsupportedError("PBKDF2 的 iterationCount 为 %d,无效" % rounds)
    keylen = None
    if pos < len(der) and der[pos] == 0x02:
        raw, pos = der_read(der, pos, 0x02, "PBKDF2 keyLength")
        keylen = int.from_bytes(raw, "big")
    prf = "sha1"  # RFC 8018 的默认伪随机函数
    if pos < len(der) and der[pos] == 0x30:
        prf_algid, pos = der_read(der, pos, 0x30, "PBKDF2 prf")
        prf_oid, _rest = der_read(prf_algid, 0, 0x06, "PBKDF2 prf oid")
        prf_name = oid_to_str(prf_oid)
        if prf_name not in PRF_OIDS:
            raise KdfUnsupportedError("不支持的 PBKDF2 伪随机函数 %s" % prf_name)
        prf = PRF_OIDS[prf_name]
    if pos != len(der):
        raise KdfUnsupportedError("PBKDF2 参数末尾有多余数据,当前参数不受支持")
    return salt, rounds, keylen, prf


def parse_pbes2(der):
    """解析 EncryptedPrivateKeyInfo 的 PBES2 参数,返回解密所需的一切。"""
    seq, end = der_read(der, 0, 0x30, "EncryptedPrivateKeyInfo")
    if end != len(der):
        raise ConvertError("EncryptedPrivateKeyInfo 末尾有多余数据")
    algid, pos = der_read(seq, 0, 0x30, "encryptionAlgorithm")
    oid, algid_pos = der_read(algid, 0, 0x06, "encryptionAlgorithm oid")
    alg_name = oid_to_str(oid)
    if alg_name != OID_PBES2:
        raise KdfUnsupportedError(
            "只支持 PBES2 加密的 PKCS#8 私钥,该文件的加密算法是 %s" % alg_name)
    params, params_end = der_read(algid, algid_pos, 0x30, "PBES2-params")
    if params_end != len(algid):
        raise CorruptKeyError("PBES2 AlgorithmIdentifier 末尾有多余数据")

    kdf_algid, params_pos = der_read(params, 0, 0x30, "PBES2 keyDerivationFunc")
    kdf_oid, kdf_pos = der_read(kdf_algid, 0, 0x06, "keyDerivationFunc oid")
    kdf_name = oid_to_str(kdf_oid)
    if kdf_name != OID_PBKDF2:
        raise KdfUnsupportedError("只支持 PBKDF2 口令派生,该文件的 KDF 是 %s" % kdf_name)
    kdf_params, kdf_end = der_read(kdf_algid, kdf_pos, 0x30, "PBKDF2-params")
    if kdf_end != len(kdf_algid):
        raise CorruptKeyError("PBKDF2 AlgorithmIdentifier 末尾有多余数据")
    salt, rounds, keylen, prf = parse_pbkdf2_params(kdf_params)

    enc_algid, params_pos = der_read(params, params_pos, 0x30, "PBES2 encryptionScheme")
    enc_oid, enc_pos = der_read(enc_algid, 0, 0x06, "encryptionScheme oid")
    enc_name = oid_to_str(enc_oid)
    if enc_name == OID_DES_EDE3_CBC:
        raise KdfUnsupportedError(
            "不支持 des-ede3-cbc 加密的 PKCS#8 私钥,请改用 -aes-256-cbc 重新导出后再转换")
    if enc_name not in CBC_CIPHERS:
        raise KdfUnsupportedError(
            "不支持的私钥加密算法 %s;本脚本只支持 %s"
            % (enc_name, "、".join(sorted({name for name, _ in CBC_CIPHERS.values()}))))
    cipher_name, key_len = CBC_CIPHERS[enc_name]
    iv, enc_end = der_read(enc_algid, enc_pos, 0x04, "encryptionScheme iv")
    if enc_end != len(enc_algid):
        raise CorruptKeyError("encryptionScheme AlgorithmIdentifier 末尾有多余数据")
    if len(iv) != AES_BLOCK:
        raise CorruptKeyError("AES-CBC 的 IV 长度是 %d 字节,应为 %d" % (len(iv), AES_BLOCK))
    if keylen is not None and keylen != key_len:
        raise KdfUnsupportedError(
            "PBKDF2 声明的密钥长度是 %d 字节,与 %s 要求的 %d 字节不一致"
            % (keylen, cipher_name, key_len))
    if params_pos != len(params):
        raise CorruptKeyError("PBES2-params 末尾有多余数据")

    data, data_end = der_read(seq, pos, 0x04, "encryptedData")
    if data_end != len(seq):
        raise CorruptKeyError("EncryptedPrivateKeyInfo 私钥字段后有多余数据")
    if not data or len(data) % AES_BLOCK:
        raise CorruptKeyError(
            "加密数据长 %d 字节,不是 %d 的整数倍,私钥可能已损坏" % (len(data), AES_BLOCK))
    return {"cipher": cipher_name, "key_len": key_len, "iv": iv,
            "salt": salt, "rounds": rounds, "prf": prf, "data": data}


def describe_pbes2(params):
    """给出一条可读的加密参数摘要,便于确认口令提示对应的是哪份文件。"""
    return ("PBES2,cipher=%s,kdf=PBKDF2-HMAC-%s,salt=%d 字节,iterationCount=%d"
            % (params["cipher"], params["prf"].upper(),
               len(params["salt"]), params["rounds"]))


def decrypt_pkcs8(params, passphrase):
    """按 PBES2 参数派生密钥并解密,返回明文 PKCS#8 的 DER。"""
    key = hashlib.pbkdf2_hmac(params["prf"], passphrase, params["salt"],
                              params["rounds"], params["key_len"])
    plain = aes_cbc_decrypt(key, params["iv"], params["data"])
    return strip_pkcs7(plain, AES_BLOCK)


# ---------------------------------------------------------------------------
# 口令来源:参数 > 环境变量 > 交互提示
# ---------------------------------------------------------------------------

def stdin_is_console():
    """判断标准输入能否安全地接受交互输入。

    Windows 上 /dev/null 这类字符设备的 isatty() 也会返回真,但 getpass 在那里
    读不到任何输入、只会一直等,所以在 Windows 上再用 GetConsoleMode 确认句柄
    确实是控制台。探测不出结果时按"不是控制台"处理。
    """
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt
    except ImportError:
        return False
    try:
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        mode = ctypes.c_uint32()
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except Exception:
        return False


def prompt_passphrase(prompt_text):
    """交互式读取口令,不回显。"""
    try:
        return getpass.getpass(prompt_text)
    except EOFError:
        raise PassphraseError("没有读到口令(输入被关闭),已取消")


def unlock_pkcs8(der, cli_passphrase):
    """取输入私钥口令并解密 PKCS#8,返回 (seed, 明文 DER)。"""
    params = parse_pbes2(der)
    sys.stdout.write("检测到 PKCS#8 私钥已加密:%s\n" % describe_pbes2(params))

    def attempt(value, source_name):
        if not value:
            raise PassphraseError("%s 给的是空口令;带口令私钥的口令至少 1 个字符" % source_name)
        plain = decrypt_pkcs8(params, value.encode("utf-8"))
        return parse_pkcs8(plain), plain

    if cli_passphrase is not None:
        return attempt(cli_passphrase, "--passphrase")
    env_value = os.environ.get(PASSPHRASE_ENV)
    if env_value is not None:
        return attempt(env_value, "环境变量 %s" % PASSPHRASE_ENV)
    if not stdin_is_console():
        raise PassphraseError(
            "私钥已加密,但当前不是交互终端,无法提示输入口令;"
            "请用 --passphrase 或环境变量 %s 提供口令" % PASSPHRASE_ENV)
    for attempt_index in range(1, PROMPT_ATTEMPTS + 1):
        value = prompt_passphrase("请输入 PEM 私钥口令(不回显):")
        try:
            return attempt(value, "交互输入")
        except PassphraseError:
            sys.stderr.write("第 %d/%d 次口令不正确\n" % (attempt_index, PROMPT_ATTEMPTS))
    raise PassphraseError("连续 %d 次口令都不正确,已放弃" % PROMPT_ATTEMPTS)


def resolve_output_passphrase(cli_value):
    """取输出私钥口令:参数 > 环境变量 > 交互提示(要求连续两次一致)。"""
    if cli_value is not None:
        if not cli_value:
            raise PassphraseError(
                "--output-passphrase 给的是空口令;带口令私钥的口令至少 1 个字符")
        return cli_value.encode("utf-8")
    env_value = os.environ.get(OUTPUT_PASSPHRASE_ENV)
    if env_value is not None:
        if not env_value:
            raise PassphraseError("环境变量 %s 是空字符串" % OUTPUT_PASSPHRASE_ENV)
        return env_value.encode("utf-8")
    if not stdin_is_console():
        raise PassphraseError(
            "--encrypt-output 需要口令,但当前不是交互终端,无法提示输入;"
            "请用 --output-passphrase 或环境变量 %s 提供口令" % OUTPUT_PASSPHRASE_ENV)
    for attempt_index in range(1, PROMPT_ATTEMPTS + 1):
        first = prompt_passphrase("请设置输出私钥口令(不回显):")
        second = prompt_passphrase("请再输入一次输出私钥口令(不回显):")
        if first != second:
            sys.stderr.write("第 %d/%d 次两次输入不一致\n" % (attempt_index, PROMPT_ATTEMPTS))
            continue
        if not first:
            raise PassphraseError("输出私钥口令不能为空")
        return first.encode("utf-8")
    raise PassphraseError("连续 %d 次两次输入不一致,已放弃" % PROMPT_ATTEMPTS)


def validate_output_cipher(cipher, rounds):
    """输出带口令私钥前先校验算法与轮数,免得采完口令才报错。"""
    if cipher not in CTR_CIPHERS:
        raise KdfUnsupportedError(
            "不支持的输出加密算法 cipher=%s;本脚本只支持 %s"
            % (cipher, "、".join(sorted(CTR_CIPHERS))))
    if rounds < 1:
        raise KdfUnsupportedError("--rounds 为 %d,至少为 1" % rounds)

def oid_to_str(raw):
    """把 OID 内容字节渲染成点分形式,用于比对算法与报错。"""
    if not raw:
        raise CorruptKeyError("OID 内容为空,无法识别算法")
    first = raw[0]
    if first < 40:
        values = [0, first]
    elif first < 80:
        values = [1, first - 40]
    else:
        values = [2, first - 80]
    acc = 0
    pending = False
    for byte in raw[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        pending = True
        if not byte & 0x80:
            values.append(acc)
            acc = 0
            pending = False
    if pending:
        raise CorruptKeyError("OID 末字节被截断")
    return ".".join(str(v) for v in values)


def extract_seed(octets):
    """从 PKCS#8 的 privateKey OCTET STRING 内容里取出 32 字节种子。"""
    if octets and octets[0] == 0x04:
        inner, end = der_read(octets, 0, 0x04, "Ed25519 私钥")
        if end == len(octets) and len(inner) == 32:
            return inner
    if len(octets) == 32:
        return octets
    raise CorruptKeyError("Ed25519 私钥应为嵌套的 32 字节 OCTET STRING,实际长度 %d" % len(octets))


def parse_pkcs8(der):
    """解析无口令的 Ed25519 PrivateKeyInfo,返回 32 字节种子。"""
    seq, end = der_read(der, 0, 0x30, "PKCS#8")
    if end != len(der):
        raise CorruptKeyError("PKCS#8 末尾有多余数据")
    version, p = der_read(seq, 0, 0x02, "PKCS#8 version")
    if version != b"\x00":
        raise CorruptKeyError("PKCS#8 版本不是 0,可能是带口令的 EncryptedPrivateKeyInfo")
    algid, p = der_read(seq, p, 0x30, "PKCS#8 algorithm")
    oid, q = der_read(algid, 0, 0x06, "algorithm oid")
    if oid != OID_ED25519[2:]:
        raise UnsupportedKeyTypeError("只支持 Ed25519,输入私钥算法是 %s" % oid_to_str(oid))
    if q != len(algid):
        raise CorruptKeyError("Ed25519 的 AlgorithmIdentifier 不应带参数")
    octets, p = der_read(seq, p, 0x04, "PKCS#8 privateKey")
    if p != len(seq):
        raise CorruptKeyError("PKCS#8 私钥字段后有多余数据")
    return extract_seed(octets)


def spki_public_key(der):
    """从 SPKI DER 中取出 32 字节 Ed25519 公钥。"""
    seq, end = der_read(der, 0, 0x30, "SPKI")
    if end != len(der):
        raise CorruptKeyError("SPKI 末尾有多余数据")
    algid, p = der_read(seq, 0, 0x30, "SPKI algorithm")
    oid, _ = der_read(algid, 0, 0x06, "SPKI algorithm oid")
    if oid != OID_ED25519[2:]:
        raise UnsupportedKeyTypeError("只支持 Ed25519,输入公钥算法是 %s" % oid_to_str(oid))
    bits, p = der_read(seq, p, 0x03, "SPKI bit string")
    if p != len(seq):
        raise CorruptKeyError("SPKI 结构末尾有多余数据")
    if not bits or bits[0] != 0x00:
        raise CorruptKeyError("SPKI 位串未按字节对齐")
    key = bits[1:]
    if len(key) != 32:
        raise CorruptKeyError("SPKI 中 Ed25519 公钥长度应为 32 字节,实际 %d" % len(key))
    return key


def parse_kdf_options(kdfopts):
    """kdfoptions 的内容是 string salt 加 uint32 rounds,OpenSSH 只用 bcrypt 这一种。"""
    salt, pos = ssh_read_string(kdfopts, 0, "kdfoptions.salt", KdfUnsupportedError)
    if pos + 4 > len(kdfopts):
        raise KdfUnsupportedError("kdfoptions 里取不到 rounds,无法派生密钥")
    rounds = int.from_bytes(kdfopts[pos:pos + 4], "big")
    if pos + 4 != len(kdfopts):
        raise KdfUnsupportedError("kdfoptions 末尾有多余数据,当前 KDF 参数不受支持")
    return salt, rounds


def read_checkint(section):
    """私有段开头是两半相同的 checkint,用来分辨口令对错与结构是否完整。"""
    if len(section) < 8:
        raise CorruptKeyError("OpenSSH 私钥的私有段被截断")
    return int.from_bytes(section[0:4], "big"), int.from_bytes(section[4:8], "big")


def parse_container(der):
    """解析 openssh-key-v1 容器头部,返回各字段。

    顺序固定为:magic、string ciphername、string kdfname、string kdfoptions、
    uint32 nkeys、string publickey、string private。
    """
    if not der.startswith(SSH_MAGIC):
        raise ConvertError("不是 openssh-key-v1 结构")
    pos = len(SSH_MAGIC)
    cipher, pos = ssh_read_string(der, pos, "ciphername", CorruptKeyError)
    kdf, pos = ssh_read_string(der, pos, "kdfname", CorruptKeyError)
    kdfopts, pos = ssh_read_string(der, pos, "kdfoptions", CorruptKeyError)
    if pos + 4 > len(der):
        raise CorruptKeyError("OpenSSH 结构被截断:公钥数量")
    nkeys = int.from_bytes(der[pos:pos + 4], "big")
    pos += 4
    if nkeys != 1:
        raise ConvertError("只支持单密钥文件,该文件包含 %d 个密钥" % nkeys)
    public, pos = ssh_read_string(der, pos, "public key", CorruptKeyError)
    section, pos = ssh_read_string(der, pos, "private section", CorruptKeyError)
    if pos != len(der):
        raise CorruptKeyError("OpenSSH 私钥末尾有多余数据")
    return {"cipher": cipher, "kdf": kdf, "kdfopts": kdfopts,
            "nkeys": nkeys, "public": public, "private": section}


def decrypt_private_section(header, passphrase):
    """按头部字段派生密钥并解密私有段,返回明文私有段。"""
    cipher_name = header["cipher"].decode("ascii", "replace")
    if cipher_name not in CTR_CIPHERS:
        raise KdfUnsupportedError(
            "不支持的私钥加密算法 ciphername=%s;本脚本只支持 %s"
            % (cipher_name, "、".join(sorted(CTR_CIPHERS))))
    if header["kdf"] != b"bcrypt":
        raise KdfUnsupportedError(
            "不支持的密钥派生函数 kdfname=%s;本脚本只支持 bcrypt"
            % header["kdf"].decode("ascii", "replace"))
    salt, rounds = parse_kdf_options(header["kdfopts"])
    if rounds < 1:
        raise KdfUnsupportedError("kdfoptions 里的 rounds 为 %d,无法派生密钥" % rounds)
    ciphertext = header["private"]
    if not ciphertext or len(ciphertext) % AES_BLOCK:
        raise CorruptKeyError(
            "加密私有段长 %d 字节,不是 %d 的整数倍,私钥可能已损坏"
            % (len(ciphertext), AES_BLOCK))
    keylen = CTR_CIPHERS[cipher_name]
    keymat = bcrypt_pbkdf(passphrase, salt, keylen + AES_BLOCK, rounds)
    plain = aes_ctr_crypt(keymat[:keylen], keymat[keylen:], ciphertext)
    first, second = read_checkint(plain)
    if first != second:
        raise PassphraseError(
            "口令不正确:解密后 checkint 两半不一致(0x%08X 与 0x%08X);"
            "若口令确认无误,则私钥可能已损坏" % (first, second))
    return plain


def open_private_section(header, passphrase=None):
    """返回明文私有段:无口令容器直接取,加密容器用口令解开。"""
    if header["cipher"] == b"none":
        if header["kdf"] != b"none" or header["kdfopts"]:
            raise CorruptKeyError(
                "容器头部 ciphername 为 none,但 kdfname 不是 none 或 kdfoptions 非空,"
                "头部字段自相矛盾,私钥可能已损坏")
        return header["private"]
    if passphrase is None:
        raise PassphraseError("该 OpenSSH 私钥带口令,但没有可用于回读校验的口令")
    return decrypt_private_section(header, passphrase)


def parse_private_section(priv_blob, pub_outer):
    """解析明文私有段,返回 (seed, pub)。"""
    first, second = read_checkint(priv_blob)
    if first != second:
        raise CorruptKeyError(
            "checkint 两半不一致(0x%08X 与 0x%08X),私钥可能已损坏或被篡改"
            % (first, second))
    pos = 8
    keytype, pos = ssh_read_string(priv_blob, pos, "keytype", CorruptKeyError)
    if keytype != SSH_KEYTYPE:
        raise UnsupportedKeyTypeError(
            "只支持 Ed25519,私钥类型是 %s" % keytype.decode("ascii", "replace"))
    pub, pos = ssh_read_string(priv_blob, pos, "public key", CorruptKeyError)
    priv, pos = ssh_read_string(priv_blob, pos, "private key", CorruptKeyError)
    _comment, pos = ssh_read_string(priv_blob, pos, "comment", CorruptKeyError)
    if len(pub) != 32:
        raise CorruptKeyError("Ed25519 公钥长度应为 32 字节,实际 %d" % len(pub))
    if len(priv) != 64:
        raise CorruptKeyError("Ed25519 私钥长度应为 64 字节,实际 %d" % len(priv))
    if priv[32:] != pub:
        raise CorruptKeyError("私钥后半段与公钥字段不一致,私钥可能已损坏")
    if pub_outer != ssh_string(SSH_KEYTYPE) + ssh_string(pub):
        raise CorruptKeyError("外层公钥与私有段内的公钥不一致")
    pad = priv_blob[pos:]
    if pad != bytes(range(1, len(pad) + 1)):
        raise CorruptKeyError("填充字节不符合 openssh-key-v1 约定")
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


def pad_private_section(body, block):
    """按 openssh-key-v1 约定填充 1、2、3... 直到长度为 block 的整数倍。"""
    pad = block - (len(body) % block)
    return body + bytes(range(1, pad + 1))


def build_openssh_private(seed, pub, passphrase=None, cipher=DEFAULT_CIPHER,
                          rounds=DEFAULT_ROUNDS):
    """按 openssh-key-v1 布局构造私钥 blob,返回 (blob, 公钥 blob)。

    passphrase 为空时私有段是明文,填充到 8 字节整数倍;非空时用 bcrypt_pbkdf
    派生 key 与 iv、以 AES-CTR 加密私有段,填充到 16 字节整数倍,与 ssh-keygen 一致。
    """
    check = os.urandom(4)
    body = check + check
    body += ssh_string(SSH_KEYTYPE)
    body += ssh_string(pub)
    body += ssh_string(seed + pub)
    body += ssh_string(b"")
    pub_blob = ssh_string(SSH_KEYTYPE) + ssh_string(pub)

    out = SSH_MAGIC
    if passphrase:
        validate_output_cipher(cipher, rounds)
        keylen = CTR_CIPHERS[cipher]
        salt = os.urandom(KDF_SALT_BYTES)
        sys.stderr.write(
            "正在用 bcrypt_pbkdf(rounds=%d)派生输出私钥的密钥,纯 Python 实现通常需要数秒\n"
            % rounds)
        keymat = bcrypt_pbkdf(passphrase, salt, keylen + AES_BLOCK, rounds)
        section = aes_ctr_crypt(keymat[:keylen], keymat[keylen:],
                                pad_private_section(body, AES_BLOCK))
        kdfopts = ssh_string(salt) + rounds.to_bytes(4, "big")
        out += ssh_string(cipher.encode("ascii"))
        out += ssh_string(b"bcrypt")
        out += ssh_string(kdfopts)
    else:
        section = pad_private_section(body, 8)
        out += ssh_string(b"none")
        out += ssh_string(b"none")
        out += ssh_string(b"")
    out += (1).to_bytes(4, "big")
    out += ssh_string(pub_blob)
    out += ssh_string(section)
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
    if status == "encrypted":
        return "(带口令私钥,已用同一口令回读自校验;ssh-keygen 需要交互输入口令,已跳过该步)"
    return "(未找到 ssh-keygen,已跳过该步校验)"


def verify_openssh_private(path, seed, pub, passphrase=None):
    with open(path, "rb") as handle:
        _label, der = pem_decode(handle.read().decode("utf-8"))
    header = parse_container(der)
    encrypted = header["cipher"] != b"none"
    section = open_private_section(header, passphrase)
    got_seed, got_pub = parse_private_section(section, header["public"])
    if got_seed != seed:
        raise ConvertError("自校验失败:转换后私钥的种子与输入私钥不一致")
    if got_pub != pub:
        raise ConvertError("自校验失败:转换后私钥内嵌的公钥与输入公钥不一致")
    if encrypted:
        return "encrypted"
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


def validate_output_dir(path):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise ConvertError("输出目录不存在:%s" % directory)


def derive_public_from_pkcs8(plain_der, output_path):
    """把解密后的 PKCS#8 写进临时文件,用 openssl 派生公钥,随后立刻删除临时文件。"""
    validate_output_dir(output_path)
    directory = os.path.dirname(os.path.abspath(output_path))
    fd, tmp = tempfile.mkstemp(prefix=".convert-key-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem_encode("PRIVATE KEY", plain_der).encode("utf-8"))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        run_openssl(["pkey", "-in", tmp, "-noout"])
        return spki_public_key(
            run_openssl(["pkey", "-in", tmp, "-pubout", "-outform", "DER"]))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def finish_private_key(seed, pub, output_path, out_passphrase, cipher, rounds):
    """写出 OpenSSH 私钥并自校验;out_passphrase 为 None 时输出不带口令。"""
    blob, _pub_blob = build_openssh_private(seed, pub, out_passphrase, cipher, rounds)
    status = write_atomic(
        output_path,
        pem_encode("OPENSSH PRIVATE KEY", blob),
        lambda tmp: verify_openssh_private(tmp, seed, pub, out_passphrase),
        secret=True)
    sys.stdout.write("已写入 %s\n" % output_path)
    if out_passphrase:
        sys.stdout.write(
            "自校验通过:回读结构一致,公钥与 PEM 派生公钥一致;"
            "输出私钥已用 %s 加密,使用时需要输入口令,"
            "ssh-keygen 复核需要交互输入口令,已跳过该步\n" % cipher)
    else:
        sys.stdout.write("自校验通过:回读结构一致,公钥与 PEM 派生公钥一致%s\n"
                         % ssh_keygen_suffix(status))


def convert(input_path, output_path, passphrase=None, encrypt_output=False,
            output_passphrase=None, cipher=DEFAULT_CIPHER, rounds=DEFAULT_ROUNDS):
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
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN EC PRIVATE KEY" in text:
        raise UnsupportedKeyTypeError("只支持 Ed25519,输入是 RSA 或 EC 的 PKCS#1、SEC1 私钥")

    out_passphrase = None
    if encrypt_output:
        validate_output_cipher(cipher, rounds)
        out_passphrase = resolve_output_passphrase(output_passphrase)
    elif output_passphrase:
        sys.stderr.write("提示:未指定 --encrypt-output,已忽略 --output-passphrase\n")

    if "BEGIN ENCRYPTED PRIVATE KEY" in text:
        label, der = pem_decode(text)
        if label != "ENCRYPTED PRIVATE KEY":
            raise ConvertError("PEM 标签是 %s,不是 ENCRYPTED PRIVATE KEY" % label)
        seed, plain_der = unlock_pkcs8(der, passphrase)
        pub = derive_public_from_pkcs8(plain_der, output_path)
        finish_private_key(seed, pub, output_path, out_passphrase, cipher, rounds)
        return

    if "BEGIN PRIVATE KEY" in text:
        label, der = pem_decode(text)
        if label != "PRIVATE KEY":
            raise ConvertError("PEM 标签是 %s,不是 PRIVATE KEY" % label)
        if passphrase:
            sys.stderr.write("提示:输入私钥未加密,已忽略所提供的口令\n")
        seed = parse_pkcs8(der)
        run_openssl(["pkey", "-in", input_path, "-noout"])
        pub = spki_public_key(
            run_openssl(["pkey", "-in", input_path, "-pubout", "-outform", "DER"]))
        finish_private_key(seed, pub, output_path, out_passphrase, cipher, rounds)
        return

    if "BEGIN PUBLIC KEY" in text:
        if encrypt_output:
            raise ConvertError("--encrypt-output 只对私钥有效;公钥是公开材料,不需要口令")
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
        "无法识别的输入格式:只接受 PKCS#8 私钥(-----BEGIN PRIVATE KEY-----、"
        "-----BEGIN ENCRYPTED PRIVATE KEY-----)或 SPKI 公钥(-----BEGIN PUBLIC KEY-----)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="把 OpenSSL PEM 格式的 Ed25519 密钥转换为 OpenSSH 格式"
                    "(openssh-key-v1、ssh-ed25519);支持带口令的 PKCS#8 输入,"
                    "并可按需输出带口令的 OpenSSH 私钥。")
    parser.add_argument(
        "input", help="输入文件:PKCS#8 私钥(可带口令)或 SPKI 公钥")
    parser.add_argument("-o", "--output", help="输出文件,缺省为 <输入文件>.converted")
    parser.add_argument(
        "-p", "--passphrase",
        help="带口令输入私钥的口令;省略时读环境变量 %s,"
             "都没有且私钥确实带口令时才交互提示输入。命令行参数会留在 shell 历史与进程列表里,"
             "本机使用更推荐环境变量或交互输入" % PASSPHRASE_ENV)
    parser.add_argument(
        "--encrypt-output", action="store_true",
        help="输出带口令的 OpenSSH 私钥;不给该参数时输出与历史行为一致,不带口令")
    parser.add_argument(
        "--output-passphrase",
        help="输出私钥的口令;省略时读环境变量 %s,"
             "都没有且需要写带口令私钥时才交互提示输入(要求连续两次一致)。"
             "命令行参数会留在 shell 历史与进程列表里" % OUTPUT_PASSPHRASE_ENV)
    parser.add_argument(
        "--cipher", default=DEFAULT_CIPHER, choices=sorted(CTR_CIPHERS),
        help="输出私钥的加密算法,默认 %s;只在 --encrypt-output 时生效" % DEFAULT_CIPHER)
    parser.add_argument(
        "--rounds", type=int, default=DEFAULT_ROUNDS,
        help="输出私钥 bcrypt_pbkdf 的轮数,默认 %d;只在 --encrypt-output 时生效,"
             "轮数越大越慢" % DEFAULT_ROUNDS)
    force_utf8()
    args = parser.parse_args(argv)

    output_path = args.output or (args.input + ".converted")
    try:
        convert(args.input, output_path, args.passphrase, args.encrypt_output,
                args.output_passphrase, args.cipher, args.rounds)
    except ConvertError as exc:
        sys.stderr.write("错误:%s\n" % exc)
        return exc.exit_code
    except OSError as exc:
        sys.stderr.write("错误:%s\n" % exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        sys.stderr.write("\n已取消\n")
        return 130
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
