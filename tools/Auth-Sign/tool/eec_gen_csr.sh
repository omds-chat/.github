# 终端签名证书 CSR,仅用 openssl
openssl req -new -key _EEC_PRIVATE_KEY_ -out _EEC_CSR_ -subj "/O=_YOUR_ORG_NAME_/CN=_YOUR_SIGNER_NAME_"
