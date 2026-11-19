# 作者密钥对,仅用 openssl:Ed25519,与产品侧校验算法保持一致
openssl genpkey -algorithm ed25519 -out _AUTHOR_PRIVATE_KEY_
openssl pkey -in _AUTHOR_PRIVATE_KEY_ -pubout -out _AUTHOR_PRIVATE_KEY_.pub
