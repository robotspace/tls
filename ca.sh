mkdir ca server client
cd ca
#生成根证书私钥(pem文件)
openssl genrsa -out ca-key.pem 2048

#生成根证书签发申请文件(csr文件)
openssl req -new -key ca-key.pem -out ca.csr -subj "/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=myCA"

#自签发根证书(cer文件) 
openssl x509 -req -days 36500 -sha1 -extensions v3_ca -signkey ca-key.pem -in ca.csr -out  ca-cert.pem

cd ../server
#生成服务端私钥
openssl genrsa -out server-key.pem 2048

#生成证书请求文件
openssl req -new -key server-key.pem -out server.csr -subj "/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=127.0.0.1"

#使用根证书签发服务端证书
openssl x509 -req -days 36500 -sha1 -extensions v3_req -CA ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem -CAserial ca.srl -CAcreateserial -in server.csr -out server-cert.pem

#使用CA证书验证server端证书
openssl verify -CAfile ../ca/ca-cert.pem  server-cert.pem

cd ../client
#生成客户端私钥
openssl genrsa  -out client-key.pem 2048
#生成证书请求文件
openssl req -new -key client-key.pem -out client.csr -subj "/C=CN/ST=myprovince/L=mycity/O=myorganization/OU=mygroup/CN=127.0.0.1"
#使用根证书签发客户端证书
openssl x509 -req -days 36500 -sha1 -extensions v3_req -CA  ../ca/ca-cert.pem -CAkey ../ca/ca-key.pem  -CAserial ../server/ca.srl -in client.csr -out client-cert.pem
#使用CA证书验证客户端证书
openssl verify -CAfile ../ca/ca-cert.pem  client-cert.pem



