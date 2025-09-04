import base64

encoded = "MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM"

# Add padding to make length a multiple of 8
while len(encoded) % 8 != 0:
    encoded += '='

decoded = base64.b32decode(encoded)
print(decoded)



