#!/usr/bin/env python
import sys
import os
import keyExchange
import registration
import audit
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.exceptions import InvalidTag
from os import path

# Returns the polling master key and generates one if it doesn't exist
def getPollingMasterKey():
    keyFileName = "pollingKey.txt"
    key = None
    
    if path.exists(keyFileName):
        file = open(keyFileName, 'rb')
        key = file.read() 
        file.close()
    else:
        key = Fernet.generate_key()
        file = open(keyFileName, 'wb')
        file.write(key)
        file.close()

    return key    

# Contacts the registration server to determine if the given voter ID is registered. Returns true
# if the voter is registered
def isRegisteredVoter(voterId):
    keyExchange.completeExchange("Polling", "Registration")

    # Get shared key
    file = open("PollingToRegistrationSharedKey.txt", 'r') 
    sharedKey = file.read()
    
    key = AESGCM.generate_key(bit_length = 128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    voterIdBytes = aesgcm.encrypt(nonce, voterId.encode(), None)

    ctr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = ctr)
    
    keyToSend = cipher.encrypt(key)
    nonceToSend = cipher.encrypt(nonce)    

    response = registration.checkVoterStatus(voterIdBytes, nonceToSend, keyToSend)

    receivedMessageCtr = Counter.new(128)
    receivedMessageCipher = AES.new(sharedKey, AES.MODE_CTR, counter = receivedMessageCtr)
    decryptedKey = receivedMessageCipher.decrypt(response[2])
    decryptedNonce = receivedMessageCipher.decrypt(response[1])
    
    aesgcm = AESGCM(decryptedKey)
    statusBytes = aesgcm.decrypt(decryptedNonce, response[0], None)
    status = eval(statusBytes.decode("utf-8"))

    return status

# Retrieves the list of recorded transaction IDs from the polled voters dictionary.
# Returns the transaction IDs as a comma-delimited string with the nonce and key to decrypt the message
def getRecordedTransactionIds():
    keyExchange.completeExchange("Polling", "Audit")

    # Get shared key
    file = open("PollingToAuditSharedKey.txt", 'r') 
    sharedKey = file.read()

    masterKey = getPollingMasterKey()
    polledVotersDictionary = getPolledVotersDictionary(masterKey)
    transactionIds = ",".join(polledVotersDictionary.values())

    if transactionIds:
        pass
    else:
        transactionIds = "No votes"
    
    key = AESGCM.generate_key(bit_length = 128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    messageToSendBytes = aesgcm.encrypt(nonce, transactionIds.encode(), None)

    ctr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = ctr)
    
    keyToSend = cipher.encrypt(key)
    nonceToSend = cipher.encrypt(nonce)

    return (messageToSendBytes, nonceToSend, keyToSend)   

# Transmit the vote and transaction ID to the audit server. Return true if the data was transmitted
# successfully
def transmitVote(vote, transactionId):
    keyExchange.completeExchange("Polling", "Audit")

    # Get shared key
    file = open("PollingToAuditSharedKey.txt", 'r') 
    sharedKey = file.read()

    key = AESGCM.generate_key(bit_length = 128)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    messageToSendBytes = aesgcm.encrypt(nonce, "{0},{1}".format(transactionId, vote).encode(), None)

    ctr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = ctr)
    
    keyToSend = cipher.encrypt(key)
    nonceToSend = cipher.encrypt(nonce)

    response = audit.transmitVote(messageToSendBytes, nonceToSend, keyToSend)
    responseCtr = Counter.new(128)

    receivedMessageCtr = Counter.new(128)
    receivedMessageCipher = AES.new(sharedKey, AES.MODE_CTR, counter = receivedMessageCtr)
    decryptedKey = receivedMessageCipher.decrypt(response[2])
    decryptedNonce = receivedMessageCipher.decrypt(response[1])
    
    aesgcm = AESGCM(decryptedKey)
    statusBytes = aesgcm.decrypt(decryptedNonce, response[0], None)
    status = eval(statusBytes.decode("utf-8"))

    return status

# Retrieve the polled voters dictionary and decrypt it for use with the poll server master key
def getPolledVotersDictionary(key):
    fileName = "polledVotersDictionary.txt"
    fernet = Fernet(key)
    polledVotersDictionary = {}
    
    if path.exists(fileName):
        file = open(fileName, 'r') 
        cipherText = file.read()
        file.close()

        plainText = fernet.decrypt(cipherText.encode())
        polledVotersDictionary = json.loads(plainText)

    return polledVotersDictionary  

# Update the polled voters dictionary with a new voter ID - Transaction ID pair entry
def buildDictionary(voterId, transactionId, key):
    fileName = "polledVotersDictionary.txt"
    fernet = Fernet(key)
    
    idSize = 4
    polledVotersDictionary = getPolledVotersDictionary(key)

    if polledVotersDictionary:
        polledVotersDictionary.update([(voterId, transactionId)])

    else:
        polledVotersDictionary = dict({voterId: transactionId})
    
    updatedDictionaryString = json.dumps(polledVotersDictionary)
    cipherText = fernet.encrypt(updatedDictionaryString.encode())
    writeFile(cipherText.decode("utf-8"), fileName)  

# Writes the content to a file with the given file name
def writeFile(content, fileName):
    file = open(fileName, "w")
    file.write(content)
    file.close()

if __name__ == "__main__":
    if len(sys.argv) == 3:
        voterId = sys.argv[1]
        vote = sys.argv[2]
        key = getPollingMasterKey()
        
        if isRegisteredVoter(voterId):
            polledVotersDictionary = getPolledVotersDictionary(key)

            if voterId in polledVotersDictionary.keys():
                print("Voter ID {0} has already voted".format(voterId))
            else:
                transactionId = str(int(os.urandom(4).hex(), 16))

                if transmitVote(vote, transactionId):
                    buildDictionary(voterId, transactionId, key)
                    print("Successfully voted. Save your transaction ID for your records: {0}".format(transactionId))
                else:
                    print("An error occured while transmitting your vote. Please try again")
        else:
            print("Voter ID {0} is not registered".format(voterId))
    else:
        print("Operation unsuccessful")
