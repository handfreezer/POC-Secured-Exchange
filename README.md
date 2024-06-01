Simple POC for requesting params :

Client is sending a request with its own id, an IV block for AES 256 CBC ciphering, and the package name of conf wanted, the request is AES 256 EBC ciphered.

if decrypt is OK by the server, server is ciphering the answer with the IV block contains in request in a AES 256 CBC way, adding content of package requested.

Client decrypted the answer of the server using the IV block sent in the request.

The main goal is to avoid a man in the mddle attack by ciphering data with a private key never exchange on communication canal, and not re-playable because of changing contant on request and IV block for answer.
