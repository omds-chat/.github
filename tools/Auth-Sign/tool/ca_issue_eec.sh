# 用根证书签发 EEC,仅用 openssl
# openssl x509 -req 不支持 -addext,扩展必须通过 -extfile 传入
openssl x509 -req -in _EEC_CSR_ -CA _CA_CERT_ -CAkey _CA_PRIVATE_KEY_ -CAcreateserial -out _EEC_CERT_ -days 365 -extfile "$(dirname "$0")/eec_ext.cnf" -extensions eec_ext
