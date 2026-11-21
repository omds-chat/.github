#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""author_convert_openssh_to_openssl.py

把 OpenSSH 格式的 Ed25519 密钥转换为 OpenSSL PEM 格式。

    私钥  -----BEGIN OPENSSH PRIVATE KEY-----  ->  -----BEGIN PRIVATE KEY-----  (PKCS#8)
    公钥  ssh-ed25519 AAAA...                  ->  -----BEGIN PUBLIC KEY-----   (SPKI)

带口令私钥的处理路径:
    1. 先解析 openssh-key-v1 容器的头部(magic、ciphername、kdfname、kdfoptions、
       nkeys、外层公钥、私有段),只看头部字段就判断私有段是不是密文,不靠试解;
    2. ciphername 为 none:私有段是明文,直接解析;
    3. ciphername 不是 none:要求 kdfname 为 bcrypt,从 kdfoptions 取出 salt 与 rounds,
       用 bcrypt_pbkdf 派生 key 与 iv,再以 AES-CTR 解密私有段,然后走同一条解析流程;
    4. 输出永远是**不带口令**的 PKCS#8 私钥,转换结束时会提示自行保管。

约束:
    只支持 Ed25519。
    只使用 Python 标准库,不依赖 cryptography 等第三方模块;bcrypt_pbkdf 与 AES-CTR
    由本脚本自带实现。
    转换后自动用 openssl 做自校验,自校验失败则以非零退出码结束。

口令来源(优先级从高到低,只在私钥确实带口令时才会用到):
    1. --passphrase 参数;
    2. OPENSSH_KEY_PASSPHRASE 环境变量;
    3. 运行在交互终端时用 getpass 提示输入(不回显),最多 3 次机会。

退出码:
    0 成功
    1 普通错误:参数、读写、格式无法识别、自校验失败等
    2 口令错误或口令缺失
    3 KDF 或加密参数不支持
    4 不是 Ed25519
    5 私钥结构损坏

用法:
    python author_convert_openssh_to_openssl.py <输入文件> [-o <输出文件>] [--passphrase <口令>]
    python author_convert_openssh_to_openssl.py id_ed25519 -o author_secret
    python author_convert_openssh_to_openssl.py id_ed25519.pub -o author_secret.pub
    OPENSSH_KEY_PASSPHRASE=... python author_convert_openssh_to_openssl.py id_ed25519
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

PROG = "author_convert_openssh_to_openssl.py"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PASSPHRASE = 2
EXIT_KDF = 3
EXIT_KEYTYPE = 4
EXIT_CORRUPT = 5

PASSPHRASE_ENV = "OPENSSH_KEY_PASSPHRASE"
PROMPT_ATTEMPTS = 3

SSH_MAGIC = b"openssh-key-v1\x00"
SSH_KEYTYPE = b"ssh-ed25519"
OID_ED25519 = b"\x06\x03\x2b\x65\x70"
PEM_RE = re.compile(r"-----BEGIN ([A-Za-z0-9 ]+)-----\s*(.*?)-----END \1-----", re.S)

AES_BLOCK = 16
# ciphername -> 密钥字节数。这三种都是 CTR 模式,密文与明文等长,不需要去填充。
CTR_CIPHERS = {"aes128-ctr": 16, "aes192-ctr": 24, "aes256-ctr": 32}


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
# AES-CTR:只做加密方向,CTR 模式解密与加密是同一条路
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
# openssh-key-v1 容器
# ---------------------------------------------------------------------------

def parse_container(der):
    """解析 openssh-key-v1 容器,返回头部字段与外层公钥、私有段。

    顺序固定为:
        magic            "openssh-key-v1\\0"
        string ciphername    私有段的加密算法,无口令时为 "none"
        string kdfname       口令派生函数,无口令时为 "none"
        string kdfoptions    KDF 参数,无口令时为空
        uint32 nkeys         密钥数量,本脚本只接受 1
        string publickey     外层公钥 blob
        string private       私有段,带口令时是密文
    """
    if not der.startswith(SSH_MAGIC):
        raise ConvertError("不是 openssh-key-v1 结构")
    pos = len(SSH_MAGIC)
    # 头部之后的结构一旦读不出来,都是文件被截断或改坏,统一按"私钥损坏"处理
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
    # AEAD 类 cipher(chacha20-poly1305@openssh.com 等)会在私有段之后追加认证标签,
    # 这里先把剩余字节留着,由解密分支按 cipher 名给出明确的"不支持"提示。
    return {"cipher": cipher, "kdf": kdf, "kdfopts": kdfopts, "nkeys": nkeys,
            "public": public, "private": section, "trailing": der[pos:]}


def container_is_encrypted(header):
    """判断私有段是否加密:唯一依据是头部字段 ciphername。

    ciphername 为 "none" 表示私有段是明文;kdfname 应当同样为 "none" 且
    kdfoptions 为空,否则头部自相矛盾。ciphername 不是 "none" 时私有段是密文,
    必须借助 kdfname 与 kdfoptions 才能解开。不能改用"能不能解析出私钥"来判断:
    密文的随机字节同样可能凑出合法的 checkint 与填充。
    """
    return header["cipher"] != b"none"


def check_plaintext_header(header):
    """ciphername 为 none 时,头部其它字段必须同样表明无口令。"""
    if header["kdf"] != b"none" or header["kdfopts"]:
        raise CorruptKeyError(
            "容器头部 ciphername 为 none,但 kdfname 不是 none 或 kdfoptions 非空,"
            "头部字段自相矛盾,私钥可能已损坏")


def parse_kdf_options(kdfopts):
    """kdfoptions 的内容是 string salt 加 uint32 rounds,OpenSSH 只用 bcrypt 这一种。"""
    salt, pos = ssh_read_string(kdfopts, 0, "kdfoptions.salt", KdfUnsupportedError)
    if pos + 4 > len(kdfopts):
        raise KdfUnsupportedError("kdfoptions 里取不到 rounds,无法派生密钥")
    rounds = int.from_bytes(kdfopts[pos:pos + 4], "big")
    pos += 4
    if pos != len(kdfopts):
        raise KdfUnsupportedError("kdfoptions 末尾有多余数据,当前 KDF 参数不受支持")
    return salt, rounds


def describe_container(header):
    """给出一条可读的头部摘要,便于用户确认口令提示对应的是哪把钥匙。"""
    parts = ["ciphername=%s" % header["cipher"].decode("ascii", "replace"),
             "kdfname=%s" % header["kdf"].decode("ascii", "replace")]
    try:
        salt, rounds = parse_kdf_options(header["kdfopts"])
    except ConvertError:
        parts.append("kdfoptions=%d 字节(无法解析)" % len(header["kdfopts"]))
    else:
        parts.append("salt=%d 字节" % len(salt))
        parts.append("rounds=%d" % rounds)
    parts.append("nkeys=%d" % header["nkeys"])
    return ",".join(parts)


def read_checkint(section):
    """私有段开头是两半相同的 checkint,用来分辨口令对错与结构是否完整。"""
    if len(section) < 8:
        raise CorruptKeyError("OpenSSH 私钥的私有段被截断")
    return (int.from_bytes(section[0:4], "big"), int.from_bytes(section[4:8], "big"))


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
    if header["trailing"]:
        raise CorruptKeyError(
            "加密私有段之后还有 %d 字节多余数据,私钥可能已损坏" % len(header["trailing"]))
    ciphertext = header["private"]
    if not ciphertext or len(ciphertext) % AES_BLOCK:
        raise CorruptKeyError(
            "加密私有段长 %d 字节,不是 %d 的整数倍,私钥可能已损坏"
            % (len(ciphertext), AES_BLOCK))
    keylen = CTR_CIPHERS[cipher_name]
    sys.stderr.write("正在用 bcrypt_pbkdf(rounds=%d)派生密钥,纯 Python 实现通常需要数秒\n"
                     % rounds)
    keymat = bcrypt_pbkdf(passphrase, salt, keylen + AES_BLOCK, rounds)
    return aes_ctr_crypt(keymat[:keylen], keymat[keylen:], ciphertext)


def decrypt_and_check(header, passphrase):
    """解密后立刻校验 checkint,把"口令错"和"私钥坏"分流到不同退出码。"""
    plain = decrypt_private_section(header, passphrase)
    first, second = read_checkint(plain)
    if first != second:
        raise PassphraseError(
            "口令不正确:解密后 checkint 两半不一致(0x%08X 与 0x%08X);"
            "若口令确认无误,则私钥可能已损坏" % (first, second))
    return plain


def stdin_is_console():
    """判断标准输入能否安全地接受交互输入。

    Windows 上 /dev/null 这类字符设备的 isatty() 也会返回真,但 getpass 在那里
    读不到任何输入、只会一直等,所以在 Windows 上再用 GetConsoleMode 确认句柄
    确实是控制台。探测不出结果时按"不是控制台"处理,宁可让用户改用参数或环境变量,
    也不让脚本卡在提示上。
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


def prompt_passphrase():
    """交互式读取口令,不回显。"""
    try:
        return getpass.getpass("请输入 OpenSSH 私钥口令(不回显):")
    except EOFError:
        raise PassphraseError("没有读到口令(输入被关闭),已取消")


def unlock_private_section(header, passphrase):
    """按优先级取口令并解密私有段:参数 > 环境变量 > 交互输入。"""
    if passphrase is not None:
        if not passphrase:
            raise PassphraseError("--passphrase 给的是空口令;带口令的 OpenSSH 私钥口令至少 1 个字符")
        return decrypt_and_check(header, passphrase.encode("utf-8"))

    env_passphrase = os.environ.get(PASSPHRASE_ENV)
    if env_passphrase is not None:
        if not env_passphrase:
            raise PassphraseError("环境变量 %s 是空字符串" % PASSPHRASE_ENV)
        return decrypt_and_check(header, env_passphrase.encode("utf-8"))

    if not stdin_is_console():
        raise PassphraseError(
            "私钥已加密,但当前不是交互终端,无法提示输入口令;"
            "请用 --passphrase 或环境变量 %s 提供口令" % PASSPHRASE_ENV)

    for attempt in range(1, PROMPT_ATTEMPTS + 1):
        value = prompt_passphrase()
        try:
            return decrypt_and_check(header, value.encode("utf-8"))
        except PassphraseError:
            sys.stderr.write("第 %d/%d 次口令不正确\n" % (attempt, PROMPT_ATTEMPTS))
    raise PassphraseError("连续 %d 次口令都不正确,已放弃" % PROMPT_ATTEMPTS)


def parse_private_section(priv_blob, pub_outer):
    """解析明文私有段,返回 (seed, pub)。"""
    first, second = read_checkint(priv_blob)
    if first != second:
        raise CorruptKeyError(
            "checkint 两半不一致(0x%08X 与 0x%08X),私钥可能已损坏或被篡改" % (first, second))

    pos = 8
    keytype, pos = ssh_read_string(priv_blob, pos, "keytype", CorruptKeyError)
    if keytype != SSH_KEYTYPE:
        raise UnsupportedKeyTypeError("只支持 Ed25519,私钥类型是 %s"
                                      % keytype.decode("ascii", "replace"))
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
    """解析一行 ssh-ed25519 AAAA...,返回 32 字节公钥。"""
    fields = text.split()
    if len(fields) < 2:
        raise ConvertError("ssh-ed25519 公钥行格式不正确")
    if fields[0] != "ssh-ed25519":
        raise UnsupportedKeyTypeError("只支持 Ed25519,输入公钥类型是 %s" % fields[0])
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except Exception:
        raise ConvertError("公钥主体不是合法的 base64")
    keytype, pos = ssh_read_string(blob, 0, "keytype")
    if keytype != SSH_KEYTYPE:
        raise UnsupportedKeyTypeError("公钥 blob 中的类型是 %s,不是 ssh-ed25519"
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


def convert(input_path, output_path, passphrase=None):
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
        header = parse_container(der)
        encrypted = container_is_encrypted(header)
        if encrypted:
            sys.stdout.write("检测到 OpenSSH 私钥已加密:%s\n" % describe_container(header))
            section = unlock_private_section(header, passphrase)
        else:
            if header["trailing"]:
                raise CorruptKeyError("OpenSSH 私钥末尾有多余数据")
            check_plaintext_header(header)
            if passphrase:
                sys.stderr.write("提示:输入私钥未加密,已忽略所提供的口令\n")
            section = header["private"]
        seed, pub = parse_private_section(section, header["public"])
        write_atomic(output_path, pem_encode("PRIVATE KEY", build_pkcs8(seed)),
                     lambda tmp: verify_pkcs8(tmp, pub), secret=True)
        sys.stdout.write("已写入 %s\n" % output_path)
        sys.stdout.write("自校验通过:openssl pkey 可读,派生公钥与 OpenSSH 私钥内嵌公钥一致\n")
        if encrypted:
            sys.stdout.write(
                "注意:输入私钥带口令,输出文件是不带口令的 PKCS#8 私钥,"
                "任何拿到它的人都能直接使用,请自行保管(建议 chmod 600 或放进受控目录)\n")
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
        raise UnsupportedKeyTypeError("只支持 Ed25519,输入是 RSA 或 EC 的 PKCS#1、SEC1 私钥")
    for prefix in ("ssh-rsa", "ecdsa-sha2-", "ssh-dss"):
        if stripped.startswith(prefix):
            raise UnsupportedKeyTypeError("只支持 Ed25519,输入公钥类型是 %s" % prefix)
    raise ConvertError(
        "无法识别的输入格式:只接受 OpenSSH 私钥(-----BEGIN OPENSSH PRIVATE KEY-----)"
        "或 ssh-ed25519 公钥行")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="把 OpenSSH 格式的 Ed25519 密钥转换为 OpenSSL PEM 格式(PKCS#8、SPKI),"
                    "支持带口令的 OpenSSH 私钥。")
    parser.add_argument("input", help="输入文件:OpenSSH 私钥或 ssh-ed25519 公钥行")
    parser.add_argument("-o", "--output", help="输出文件,缺省为 <输入文件>.converted")
    parser.add_argument(
        "-p", "--passphrase",
        help="带口令 OpenSSH 私钥的口令;省略时读环境变量 %s,"
             "都没有且私钥确实带口令时才交互提示输入。命令行参数会留在 shell 历史与进程列表里,"
             "本地使用更推荐环境变量或交互输入" % PASSPHRASE_ENV)
    force_utf8()
    args = parser.parse_args(argv)

    output_path = args.output or (args.input + ".converted")
    try:
        convert(args.input, output_path, args.passphrase)
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
