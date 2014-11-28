.PHONY: all clean keystore truststore

KEYSTORE   := certs/keystore.p12
TRUSTSTORE := certs/truststore.jks

CA_CERT     := certs/testcacert.pem
CLIENT_KEY  := certs/clientkey.pem
CLIENT_CERT := certs/clientcert.pem

all: certs keystore truststore

clean:
	tlspretense cleancerts

certs:
	tlspretense certs

keystore: $(KEYSTORE)

truststore: $(TRUSTSTORE)

$(KEYSTORE): certs
	openssl pkcs12 -export -out $(KEYSTORE) -in $(CLIENT_CERT) -inkey $(CLIENT_KEY) -passout pass:foobar

$(TRUSTSTORE): certs
	keytool -importcert -noprompt -keystore $(TRUSTSTORE) -file $(CA_CERT) -storepass foobar
