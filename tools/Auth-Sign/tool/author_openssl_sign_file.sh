# 用 OpenSSL 私钥对文件生成裸公钥签名,仅用 openssl
openssl pkeyutl -sign -inkey _AUTHOR_PRIVATE_KEY_ -in _DATA_FILE_ -out _DATA_FILE_.sig -rawin
