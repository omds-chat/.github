# 用根证书校验 EEC 签名并检查吊销,仅用 openssl
# openssl cms -verify 没有 -CRLfile 参数,需先把 CRL 与根证书拼进同一个 PEM 文件
cat _CA_CERT_ _CRL_FILENAME_ > _CA_CRL_BUNDLE_
# -md sha512:显式指定摘要算法;验签侧实际以 SignerInfo 中的摘要为准,此参数仅作声明
#
# 空设备与重定向写法约定(MSYS / Git Bash 实测,改动前请先读完):
#   禁止:openssl ... -out /dev/null
#     原因:argv 里的 /dev/null 会被 MSYS 解析成相对名 nul,Git 自带的 openssl 把 nul
#     当成当前目录下的普通文件,于是留下 nul 垃圾文件,验签本身还可能直接失败。
#     实测证据(openssl 3.5.6,"C:/Program Files/Git/usr/bin/openssl.exe"):
#       $ openssl dgst -sha512 /dev/null
#       nul: No such file or directory
#       100000000A000000:error:80000002:system library:file_ctrl:No such file or directory:crypto/bio/bss_file.c:299:calling fopen(nul, rb)
#   禁止:>nul 与 2>nul
#     原因:那是 cmd 语义,bash 不认,会在当前目录生成名为 nul 的普通文件。
#   允许:命令末尾的 > /dev/null
#     原因:那是 bash 自己的重定向,bash 直接打开字符设备 /dev/null,不经过路径解析,
#     实测 [ -c /dev/null ] 为真,写入后不产生任何文件。
#
# stdout 被丢弃后 openssl 自身的成功提示也看不到了,所以这里显式回显结论:
# 验签通过退出码 0,验签失败退出码 1。
if openssl cms -verify -binary -inform DER -in _THE_SIGN_FILENAME_ -content _THE_SIGNED_FILENAME_ -CAfile _CA_CRL_BUNDLE_ -crl_check -md sha512 > /dev/null; then
  echo "验签通过:_THE_SIGN_FILENAME_ 与 _THE_SIGNED_FILENAME_ 内容匹配,EEC 可链到 _CA_CERT_ 且未被吊销"
else
  echo "验签失败:_THE_SIGN_FILENAME_ 与 _THE_SIGNED_FILENAME_ 不匹配,或 EEC 证书链/吊销校验未通过" >&2
  exit 1
fi
