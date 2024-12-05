# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=CA"

# Generate server private key
openssl genrsa -out server.key 2048

# Generate server CSR
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=server.local"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256

# Generate client private key
openssl genrsa -out client.key 2048

# Generate client CSR
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=client.local"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -sha256

# Export server key and certificate to PKCS12
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12 \
    -name server -CAfile ca.crt -caname root -password pass:password

# Export client key and certificate to PKCS12
openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12 \
    -name client -CAfile ca.crt -caname root -password pass:password

# Create a keystore and import the CA certificate
keytool -import -trustcacerts -file ca.crt -alias root -keystore keystore.jks -storepass password -noprompt

# Import the server PKCS12 file
keytool -importkeystore -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass password \
    -destkeystore keystore.jks -deststorepass password -alias server

# Import the client PKCS12 file
keytool -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -srcstorepass password \
    -destkeystore keystore.jks -deststorepass password -alias client
