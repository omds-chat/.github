# 根 CA 自签名证书,仅用 openssl
openssl req -x509 -new -key _CA_PRIVATE_KEY_ -days 3650 -out _CA_CERT_ -subj "/O=_YOUR_ORG_NAME_/CN=_YOUR_CA_NAME_" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash"
