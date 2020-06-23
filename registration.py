#!/usr/bin/env python
import sys
import os
import string
import datetime
import hashlib
import copy
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.exceptions import InvalidTag
from os import path

class Node:
    def __init__(self, hash):
        self.left = None
        self.right = None
        self.hash = hash

    def hasChildren(self):
        if self.left != None or self.right != None:
            return True
        else:
            return False

# aggregates a level of child nodes into parent nodes and returns the new sequence of parent nodes
def generateNextLevelNodes(previousLevelNodes):
    nextLevelNodes = []
    parentNode = None
    leftChild = None

    for index, node in enumerate(previousLevelNodes):           
        if leftChild == None:
            leftChild = node
        else:
            parentNode = Node(hashlib.sha256(leftChild.hash.encode('utf-8') + node.hash.encode('utf-8')).hexdigest())
            parentNode.left = copy.deepcopy(leftChild)
            parentNode.right = node
            nextLevelNodes.append(parentNode)
            leftChild = None

    # if there are an odd number of nodes, create a parent node for the remaining child node
    if leftChild != None:
        parentNode = Node(leftChild.hash)
        parentNode.left = copy.deepcopy(leftChild)
        nextLevelNodes.append(parentNode)
        leftChild = None

    return nextLevelNodes

# Builds a merkle tree from the given list of leaf nodes
def buildMerkleTree(leafNodes):
    rootNode = None

    # if only one name is provided, skip additional level processing because the tree is only a root     
    if len(leafNodes) > 1:
        previousLevelNodes = copy.deepcopy(leafNodes)
        nextLevelNodes = generateNextLevelNodes(previousLevelNodes)
            
        while len(nextLevelNodes) != 1:
            previousLevelNodes = copy.deepcopy(nextLevelNodes)
            nextLevelNodes = generateNextLevelNodes(previousLevelNodes)

        rootNode = nextLevelNodes[0]

    else:
        rootNode = leafNodes[0]

    return rootNode

# Returns the registered voters dictionary
def getVoterIdDictionary(key):
    fileName = "registeredVotersDictionary.txt"
    fernet = Fernet(key)
    voterIdDictionary = {}
    
    if path.exists(fileName):
        file = open(fileName, 'r') 
        cipherText = file.read()
        file.close()

        plainText = fernet.decrypt(cipherText.encode())
        voterIdDictionary = json.loads(plainText)

    return voterIdDictionary  

# Rebuilds the registered voters dictionary
def buildVoterIdDictionary(voterEntry):
    fileName = "registeredVotersDictionary.txt"
    key = getRegistrationMasterKey()
    fernet = Fernet(key)
    
    idSize = 4
    voterIdDictionary = getVoterIdDictionary(key)
    voterId = str(int(os.urandom(idSize).hex(), 16))

    if voterIdDictionary:
        while voterId in voterIdDictionary.keys():
            voterId = str(int(os.urandom(idSize).hex(), 16))
            
        voterIdDictionary.update([(voterId, voterEntry)])

    else:
        voterIdDictionary = dict({voterId: voterEntry})
    
    updatedDictionaryString = json.dumps(voterIdDictionary)
    cipherText = fernet.encrypt(updatedDictionaryString.encode())
    writeFile(cipherText.decode("utf-8"), fileName)
    
    return voterId

# Returns the merkle tree as an array
def getRegistrationMerkleTreeArray(treeFileName, getLeafNodesOnly):
    merkleTreeAsArray = []

    if path.exists(treeFileName):
        file = open(treeFileName, 'r') 
        fileLines = file.readlines()
        linesWithHashes = []

        #Filter out lines only containing whitepaces
        for line in fileLines:
            if line.strip():
                linesWithHashes.append(line)

        numberOfLines = len(linesWithHashes)
        
        indentation = 0

        if getLeafNodesOnly:
            leafNodeIndentation = 0
            
            for line in linesWithHashes:
                if line.count("\t") > leafNodeIndentation:
                    leafNodeIndentation = line.count("\t")
            # Only retrieve the leaf nodes
            for line in linesWithHashes:
                if line.count("\t") == leafNodeIndentation:
                    merkleTreeAsArray.append(line.strip())
        else:        
            #Insert each hash into the array based on the number of tab characters in the line. The greater the number of tabs, the closer to the leaves the hash is
            while len(merkleTreeAsArray) != numberOfLines:
                for line in linesWithHashes:
                    if line.count("\t") == indentation:
                        merkleTreeAsArray.append(line.strip())

                indentation = indentation + 1 

    return merkleTreeAsArray

# Returns the registration master key
def getRegistrationMasterKey():
    keyFileName = "registrationKey.txt"
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

# Generates the merkle tree as a formatted string
def generateTreeAsString(rootNode):
    tree = rootNode.hash + "\n"
    
    if (rootNode.hasChildren()):
        tree = tree + writeChildNodes(tree, rootNode, 1)
            
    return tree

# recursive function for constructing the tree for a node and all its children. Returns the tree as a string for the specified parent node
def writeChildNodes(tree, parentNode, level):
    indentation = "\t" * level

    leftChild = parentNode.left

    leftChildTree = None

    if leftChild.hasChildren():
        leftChildTree = indentation + leftChild.hash + "\n" + writeChildNodes(leftChildTree, leftChild, level + 1) + "\n"
    else:
        leftChildTree = indentation + leftChild.hash + "\n"

    rightNode = None
    rightChildTree = None
    
    if parentNode.right != None:
        rightChild = parentNode.right
        
        if rightChild.hasChildren():
            rightChildTree = indentation + rightChild.hash + "\n" + writeChildNodes(rightChildTree, rightChild, level + 1) + "\n"
        else:
            rightChildTree = indentation + rightChild.hash + "\n"

    if rightChildTree != None:
        tree = leftChildTree + rightChildTree
    else:
        tree = leftChildTree
        
    return tree

# Writes the content to a file with the given file name
def writeFile(content, fileName):
    file = open(fileName, "w")
    file.write(content)
    file.close()

# Registers a voter with the specified info if the voter isn't already registered
def registerVoter(firstName, lastName, dob):
    treeFileName = 'registrationMerkle.tree'

    merkleTreeEntry = "{0},{1},{2}".format(firstName, lastName, dob)
    entryHash = hashlib.sha256(merkleTreeEntry.encode('utf-8')).hexdigest()
    existingLeafHashes = getRegistrationMerkleTreeArray(treeFileName, True)

    if entryHash in existingLeafHashes:
        #duplicate voter
        print("Error: voter is already registered")
    else:
        #rebuild merkle tree with old leaves plus new hash
        existingLeafHashes.append(entryHash)
        leafNodes = []
        
        for index, leafHash in enumerate(existingLeafHashes):
            leafNodes.append(Node(leafHash))
            
        rootNode = buildMerkleTree(leafNodes)
        
        #add entry to voter ID file and return voter ID
        voterId = buildVoterIdDictionary("{0} {1},{2}".format(firstName, lastName, dob))
        writeFile(generateTreeAsString(rootNode), treeFileName)

        print("Registration successful. Please save your voter ID: {0}".format(voterId))

# Checks whether the provided voter ID from the poll server is registered   
def checkVoterStatus(encryptedMessageBytes, encryptedNonce, encryptedKey):
    # Get shared key
    file = open("RegistrationToPollingSharedKey.txt", 'r') 
    sharedKey = file.read()

    ctr = Counter.new(128)
    cipher = AES.new(sharedKey, AES.MODE_CTR, counter = ctr)

    decryptedKey = cipher.decrypt(encryptedKey)
    decryptedNonce = cipher.decrypt(encryptedNonce)
    aesgcm = AESGCM(decryptedKey)

    isRegistered = False
    
    # throws exception if the integrity check fails
    try:
        voterIdBytes = aesgcm.decrypt(decryptedNonce, encryptedMessageBytes, None)
        voterId = str(voterIdBytes.decode("utf-8"))
        
        # Check if voter ID is valid 
        voterIdDictionary = getVoterIdDictionary(getRegistrationMasterKey())

        if voterIdDictionary:
            if voterId in voterIdDictionary.keys():
                isRegistered = True
    except InvalidTag:
        pass

    responseKey = AESGCM.generate_key(bit_length = 128)
    aesgcm = AESGCM(responseKey)
    responseNonce = os.urandom(12)
    responseBytes = aesgcm.encrypt(responseNonce, str(isRegistered).encode(), None)

    responseCtr = Counter.new(128)
    responseCipher = AES.new(sharedKey, AES.MODE_CTR, counter = responseCtr)
    keyToSend = responseCipher.encrypt(responseKey)
    nonceToSend = responseCipher.encrypt(responseNonce)

    return (responseBytes, nonceToSend, keyToSend)
    
if __name__ == "__main__":
    if len(sys.argv) == 4:
        firstName = sys.argv[1].upper()
        lastName = sys.argv[2].upper()
        dob = sys.argv[3]

        try:           
            datetime.datetime.strptime(dob, '%m/%d/%Y')
            registerVoter(firstName, lastName, dob)
        except ValueError:
            print("Error: date must be in the correct format (MM/DD/YYYY)")
    else:
        print("Error: arguments must be in the order <first name> <last name> <D.O.B.>")
