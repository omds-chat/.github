# 吊销 EEC 并生成 CRL,仅用 openssl
# openssl crl -gen 在 OpenSSL 3.x 不可用,必须用 openssl ca -gencrl,因此需要一套最小 CA 目录

# 1) 初始化最小 CA 目录:index.txt 吊销库、serial、crlnumber
mkdir -p _CA_WORK_DIR_
[ -f _CA_WORK_DIR_/index.txt ] || : > _CA_WORK_DIR_/index.txt
[ -f _CA_WORK_DIR_/serial ] || printf '01\n' > _CA_WORK_DIR_/serial
[ -f _CA_WORK_DIR_/crlnumber ] || printf '01\n' > _CA_WORK_DIR_/crlnumber

# 2) 生成该目录专用的 openssl.cnf,并通过 .include 引入 crl.conf 的 crl_ext 扩展
printf '%s\n' \
  '[ ca ]' \
  'default_ca = CA_default' \
  '' \
  '[ CA_default ]' \
  'dir = _CA_WORK_DIR_' \
  'database = $dir/index.txt' \
  'serial = $dir/serial' \
  'crlnumber = $dir/crlnumber' \
  'certificate = _CA_CERT_' \
  'private_key = _CA_PRIVATE_KEY_' \
  '# default_md 显式写 sha512:不写则 openssl ca 取默认摘要,会随 OpenSSL 版本或密钥类型漂移' \
  'default_md = sha512' \
  'default_crl_days = 30' \
  'policy = policy_any' \
  'crl_extensions = crl_ext' \
  '' \
  '[ policy_any ]' \
  'commonName = optional' \
  'organizationName = optional' \
  'organizationalUnitName = optional' \
  'countryName = optional' \
  'stateOrProvinceName = optional' \
  'localityName = optional' \
  'emailAddress = optional' \
  '' \
  '.include = _CRL_CONF_FILENAME_' \
  > _CA_WORK_DIR_/openssl.cnf

# 3) 吊销证书;-revoke 可重复写多行;同一证书重复吊销会提示 Already revoked,不影响后续生成
openssl ca -config _CA_WORK_DIR_/openssl.cnf -revoke _EEC_CERT_ -crl_reason _THE_REASON_VALUE_ -batch

# 4) 生成 CRL
openssl ca -config _CA_WORK_DIR_/openssl.cnf -gencrl -out _CRL_FILENAME_ -crldays _HOW_LONG_
