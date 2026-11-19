# 查看任意 x509 证书的基础信息
openssl x509 -in _THE_CA_CERT_FILENAME_ -noout -serial -issuer -subject -dates

# 查看任意 x509 证书的完整信息
openssl x509 -in _THE_CA_CERT_FILENAME_ -noout -text