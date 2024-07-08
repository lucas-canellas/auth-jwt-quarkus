# GERANDO AS CHAVES

## 1
openssl genrsa -out rsaPrivateKey.pem 2048
openssl rsa -pubout -in rsaPrivateKey.pem -out publicVerificationKey.pem

## 2
openssl pkcs8 -inform PEM -in rsaPrivateKey.pem -outform PEM -out privateSigningKey.pem -topk8 -nocrypt

