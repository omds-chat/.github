# 用 OpenSSL 公钥校验裸公钥签名,仅用 openssl
openssl pkeyutl -verify -pubin -inkey _AUTHOR_PUBLIC_KEY_ -in _DATA_FILE_ -sigfile _DATA_FILE_.sig -rawin
