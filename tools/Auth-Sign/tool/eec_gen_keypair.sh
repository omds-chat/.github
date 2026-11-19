# 终端签名证书 EEC 密钥对,仅用 openssl:必须是 ECDSA P-256,否则 openssl cms -sign 会失败
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out _EEC_PRIVATE_KEY_
# 由私钥导出公钥:公钥是公开材料,可随仓库分发;私钥不得入库
openssl pkey -in _EEC_PRIVATE_KEY_ -pubout -out _EEC_PRIVATE_KEY_.pub
