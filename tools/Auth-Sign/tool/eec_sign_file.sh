# 用 EEC 对文件生成 CMS 分离签名,仅用 openssl
# 必须 -binary -outform DER,默认的 S/MIME 包装浏览器无法解析
# -md sha512:显式指定摘要算法,避免默认值随 OpenSSL 版本或密钥类型漂移
openssl cms -sign -binary -in _THE_FILENAME_ -out _THE_FILENAME_.sig -signer _EEC_CERT_ -inkey _EEC_PRIVATE_KEY_ -outform DER -noattr -md sha512
