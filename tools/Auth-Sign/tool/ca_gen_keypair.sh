# 根 CA 密钥对,仅用 openssl:生成 ECDSA P-256 私钥
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out _CA_PRIVATE_KEY_
# 由私钥导出公钥:公钥是公开材料,可随仓库分发;私钥不得入库
openssl pkey -in _CA_PRIVATE_KEY_ -pubout -out _CA_PRIVATE_KEY_.pub
