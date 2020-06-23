#!/usr/bin/env python
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

# Comples the Diffie-Hellman key exchange between 2 entities
def completeExchange(entity1, entity2):
    parameters = dh.generate_parameters(generator = 5, key_size = 512, backend = default_backend())

    entity1PrivateKey = parameters.generate_private_key()
    entity2PrivateKey = parameters.generate_private_key()
    
    entity1SharedKey = entity1PrivateKey.exchange(entity2PrivateKey.public_key())

    entity2SharedKey = entity2PrivateKey.exchange(entity1PrivateKey.public_key())

    writeFile(entity1SharedKey[:16].hex(), "{0}To{1}SharedKey.txt".format(entity1, entity2))
    writeFile(entity2SharedKey[:16].hex(), "{0}To{1}SharedKey.txt".format(entity2, entity1))

def writeFile(content, fileName):
    file = open(fileName, "w")
    file.write(content)
    file.close()
    
if __name__ == "__main__":
    if len(sys.argv) == 3:
        entity1 = sys.argv[1]
        entity2 = sys.argv[2]

        completeExchange(entity1, entity2)
    else:
        print("Operation unsuccessful")
