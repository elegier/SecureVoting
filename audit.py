#!/usr/bin/env python
import sys
import os
import keyExchange
import registration
import json
import genkeys
import polling
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.exceptions import InvalidTag
from os import path

# Returns the audit master key and creates one if it doesn't exist
def getAuditMasterKey():
    keyFileName = "auditKey.txt"
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

# Returns the audit server's private key
def getPrivateKey():
    keyFileName = "audit.priv"
    key = None
    
    if path.exists(keyFileName):
        file = open(keyFileName, 'rb')
        key = file.read().decode("utf-8") 
        file.close()
    else:
        genkeys.generateKeyPair("audit")
        file = open(keyFileName, 'rb')
        key = file.read().decode("utf-8")
        file.close()

    return key.split(",")

# Returns the audit server's public key
def getPublicKey():
    keyFileName = "audit.pub"
    key = None
    
    if path.exists(keyFileName):
        file = open(keyFileName, 'rb')
        key = file.read().decode("utf-8") 
        file.close()
    else:
        genkeys.generateKeyPair("audit")
        file = open(keyFileName, 'rb')
        key = file.read().decode("utf-8")
        file.close()

    return key.split(",")

# Returns the recorded votes dictionary as the cipher text and signature
def getRecordedVotesDictionaryText():
    fileName = "recordedVotesDictionary.txt"
    key = getAuditMasterKey()
    fernet = Fernet(key)

    fileText = None
    
    if path.exists(fileName):
        file = open(fileName, 'r') 
        fileText = file.read()
        file.close()

    return fileText

# Returns the recorded votes dictionary
def getRecordedVotesDictionary():
    fileName = "recordedVotesDictionary.txt"
    key = getAuditMasterKey()
    fernet = Fernet(key)
    recordedVotesDictionary = {}
    
    if path.exists(fileName):
        file = open(fileName, 'r') 
        fileText = file.read()
        file.close()

        cipherText = fileText.split("--END--")[0]
        plainText = fernet.decrypt(cipherText.encode())
        recordedVotesDictionary = json.loads(plainText)

    return recordedVotesDictionary  

# Updates the recorded votes dictionary with the given transaction ID - vote pair
def saveVote(transactionId, vote, recordedVotesDictionary):
    voteSaved = False

    if recordedVotesDictionary:
        if transactionId in recordedVotesDictionary.keys():
            voteSaved = False
        else:
            recordedVotesDictionary.update([(transactionId, vote)])
            voteSaved = True
    else:
        recordedVotesDictionary = dict({transactionId: vote})
        voteSaved = True

    key = getAuditMasterKey()
    fernet = Fernet(key)
    updatedDictionaryString = json.dumps(recordedVotesDictionary)
    cipherText = fernet.encrypt(updatedDictionaryString.encode())

    cipherHash = hashlib.sha256(cipherText).hexdigest()

    privateKey = getPrivateKey()
    n = privateKey[0]
    e = privateKey[1]

    encryptedHashDecimal = pow(int(cipherHash, 16), int(e), int(n))
    encryptedHashHex = "%x" % encryptedHashDecimal

    content = "{0}--END--{1}".format(cipherText.decode("utf-8"), encryptedHashHex)
    writeFile(content, "recordedVotesDictionary.txt")
    
    return voteSaved

# Writes the content to a file with the given file name
def writeFile(content, fileName):
    file = open(fileName, "w")
    file.write(content)
    file.close()

# Recieves a transaction ID and vote from the poll server and saves the information
def transmitVote(encryptedMessageBytes, encryptedNonce, encryptedKey):
    # Get shared key
    file = open("AuditToPollingSharedKey.txt", 'r') 
    sharedKey = file.read()

    ctr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = ctr)
    
    decryptedKey = cipher.decrypt(encryptedKey)
    decryptedNonce = cipher.decrypt(encryptedNonce)
    aesgcm = AESGCM(decryptedKey)

    voteSaved = False
    
    # throws exception if the integrity check fails
    try:
        messageBytes = aesgcm.decrypt(decryptedNonce, encryptedMessageBytes, None)
        message = str(messageBytes.decode("utf-8")).split(",")
        transactionId = message[0]
        vote = message[1]
        
        recordedVotesDictionary = getRecordedVotesDictionary()
        voteSaved = saveVote(transactionId, vote, recordedVotesDictionary)
                
    except InvalidTag:
        pass

    responseKey = AESGCM.generate_key(bit_length = 128)
    aesgcm = AESGCM(responseKey)
    responseNonce = os.urandom(12)
    responseBytes = aesgcm.encrypt(responseNonce, str(voteSaved).encode(), None)

    responseCtr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = responseCtr)
    
    keyToSend = cipher.encrypt(responseKey)
    nonceToSend = cipher.encrypt(responseNonce)

    return (responseBytes, nonceToSend, keyToSend)

# Verifies the vote tally. Returns an error if the recorded votes file has been tampered
def verifyTallyIntegrity(voterTallyFileText):
    content = voterTallyFileText.split("--END--")
    cipherText = content[0]
    signature = content[1]
    signatureDecimal = int(signature, 16)
        
    cipherHash = hashlib.sha256(cipherText.encode("utf-8")).hexdigest()

    publicKey = getPublicKey()
    n = publicKey[0]
    d = publicKey[1]

    decryptedSignatureDecimal = pow(signatureDecimal, int(d), int(n))
    derivedHash = "%x" % decryptedSignatureDecimal

    # add leading 0 if there is an odd number of digits
    if len(derivedHash) % 2 == 1:
        derivedHash = '0' + derivedHash

    if cipherHash == derivedHash:
        return True
    else:
        return False

# Checks if a given transaction ID is included in the recorded votes dictionary
def checkVoteInclusion(transactionId):
    fileText = getRecordedVotesDictionaryText()
    
    if fileText:
        included = False
        
        if verifyTallyIntegrity(fileText):
            recordedVotesDictionary = getRecordedVotesDictionary()

            if transactionId in recordedVotesDictionary.keys():
                included = True

        content = fileText.split("--END--")
        cipherText = content[0]
        signature = content[1]
        signatureDecimal = int(signature, 16)
        
        cipherHash = hashlib.sha256(cipherText.encode("utf-8")).hexdigest()

        publicKey = getPublicKey()
        n = publicKey[0]
        d = publicKey[1]
        
        publicKeyString = ",".join(publicKey)
        
        if included:
            print("Transaction ID {0} is included. Signature: {1}. Public Key (n,d): {2}. Total Votes Hash: {3}".format(transactionId, signature, publicKeyString, cipherHash))
        else:
            print("Transaction ID {0} is not included. Signature: {1}. Public Key (n,d): {2}. Total Votes Hash: {3}".format(transactionId, signature, publicKeyString, cipherHash))
    else:
        print("Transaction ID {0} is included because no votes have been cast".format(transactionId))

# Counts the votes
def countVotes(recordedVotesDictionary):
    if recordedVotesDictionary:
        
        candidate1Votes = sum(value == "1" for value in recordedVotesDictionary.values())
        candidate2Votes = sum(value == "2" for value in recordedVotesDictionary.values())
        return(candidate1Votes, candidate2Votes)
    
    else:
        return(0, 0)

# Verifies the vote tally    
def verifyVotes():
    fileText = getRecordedVotesDictionaryText()

    if fileText:
        content = fileText.split("--END--")
        cipherText = content[0]
        signature = content[1]
        signatureDecimal = int(signature, 16)
        
        cipherHash = hashlib.sha256(cipherText.encode("utf-8")).hexdigest()

        publicKey = getPublicKey()
        n = publicKey[0]
        d = publicKey[1]
        
        publicKeyString = ",".join(publicKey)        

        if verifyTallyIntegrity(fileText):
            response = polling.getRecordedTransactionIds()

            # Get shared key
            file = open("AuditToPollingSharedKey.txt", 'r') 
            sharedKey = file.read()
            
            receivedMessageCtr = Counter.new(128)
            receivedMessageCipher = AES.new(sharedKey, AES.MODE_CTR, counter = receivedMessageCtr)
            decryptedKey = receivedMessageCipher.decrypt(response[2])
            decryptedNonce = receivedMessageCipher.decrypt(response[1])
            
            aesgcm = AESGCM(decryptedKey)
            transactionIds = aesgcm.decrypt(decryptedNonce, response[0], None).decode("utf-8")
            
            transactionIdList = transactionIds.split(",")
            recordedVotesDictionary = getRecordedVotesDictionary()
            
            if all(elem in recordedVotesDictionary.keys() for elem in transactionIdList):
                expectedNumVotes = 0

                if transactionIds != "No votes":
                    expectedNumVotes = len(transactionIdList)
                    
                talliedVotes = countVotes(recordedVotesDictionary)
                
                candidate1Votes = talliedVotes[0]
                candidate2Votes = talliedVotes[1]

                print("Expected Total: {0}, Candidate 1 Votes: {1}, Candidate 2 Votes: {2}, Signature: {3}. Public Key (n,d): {4}, Total Votes Hash: {5}".format(expectedNumVotes, candidate1Votes, candidate2Votes, signature, publicKeyString, cipherHash))
            else:
                missingTransactions = list(set(transactionIdList) - set(recordedVotesDictionary.keys()))  
                print("Error: The following votes are missing ({0})".format(", ".join(missingTransactions)))
        else:
            print("Error: recorded votes hash does not match signature; Signature: {0}, Public Key (n,d): {1}, Total Votes Hash: {2}".format(signature, publicKeyString, cipherHash))
    else:
        print("No votes have been recorded")
        
if __name__ == "__main__":
    if len(sys.argv) > 1:
        operation = sys.argv[1]    
        key = getAuditMasterKey()

        if operation == "-c":
            transactionId = sys.argv[2] 

            if transactionId:
                checkVoteInclusion(transactionId)
                
            else:
                print("Error: please provide a transaction ID")
        elif operation == "-v":
            verifyVotes()
        else:
            print("fail")

    else:
        print("Error: please provide an operation (-c to check vote inclusion or -v to verify vote tally)")
