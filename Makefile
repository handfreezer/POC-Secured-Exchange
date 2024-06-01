all: clean
	-mkdir deps params exchange
	wget https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar -O deps/json-20240303.jar
	echo -n "clientId-$$(hostname -s)" > params/clientId.txt
	sha512sum deps/json-20240303.jar | cut -f1 > params/password.hex
	java --class-path deps/json-20240303.jar src/net/ulukai/securedparams/PocClient.java

clean:
	-rm -rf deps params exchange
	-rm src/net/ulukai/securedparams/PocClient.class

