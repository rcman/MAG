Exponent (\bm{e}) - (1 byte):
This is the public exponent. It is located at offset 0x1BE.

11  (Decimal: 17)

How to Reconstruct the Public Key (PEM format)
If you need to use this key in OpenSSL or a script, you can reconstruct the standard PEM file. Since we have the raw DER bytes, you can simply strip the proprietary header (the first 17 bytes) and save the rest.
1. Create the binary file (DER):
Save the bytes from offset 0x11 to the end (0x11 through 0x2D6) into a file named mag_cert.der.
2. Convert to PEM using OpenSSL:
Run the following command in your terminal:

openssl x509 -inform DER -in mag_cert.der -out mag_cert.pem -text

