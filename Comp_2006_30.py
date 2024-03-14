import datetime
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
import cryptography

#create a timestamp
Timestamp = datetime.datetime.now()
print(Timestamp)

#create message
m = "The company website has not limited the number of transactions a single user or device can perform in a given period of time. The transactions/time should be above the actual business requirement, but low enough to deter automated attacks."

#add timestamp to the end
M = "{} {}".format(m, Timestamp)

print(M)

#Hash the message
hashed_message = hashlib.sha256(M.encode()).digest()
print("Hashed Message:", hashed_message)

# creating a private key  
private_key = rsa.generate_private_key(
 	public_exponent=65537,
 	key_size=2048,
	backend=default_backend()
)

# Extracting the public key from the private key
public_key = private_key.public_key()

# changing to PEM so it can be printed
private_pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.TraditionalOpenSSL,
	encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:\n", private_pem.decode())
print("Public Key:\n", public_pem.decode())

# Create a digital signature using private key
def sign(M, private_key):
	padding_instance = padding.PSS(
    	mgf=padding.MGF1(hashes.SHA256()),
    	salt_length=padding.PSS.MAX_LENGTH
	)
	signature = private_key.sign(
    	M,
    	padding_instance,
    	hashes.SHA256()
	)
	return signature

# Generate the digital signature
signature = sign(hashed_message, private_key)

# Print the digital signature as a byte string
print("Digital Signature:", signature)

#this is what the message should look like
print(M)
print(hashed_message)
print(signature)

# Verify the final message

# Get info needed
original_message_hash = hashlib.sha256(M.encode()).digest()

# Extract the timestamp from the original message
extracted_timestamp = ' '.join(M.split()[-2:])

# Converting to datetime object with milliseconds
extracted_timestamp = datetime.datetime.strptime(extracted_timestamp, "%Y-%m-%d %H:%M:%S.%f")

# Verify the digital signature
try:
	public_key.verify(
    	signature,
    	original_message_hash,
    	padding.PSS(
        	mgf=padding.MGF1(hashes.SHA256()),
        	salt_length=padding.PSS.MAX_LENGTH
    	),
    	hashes.SHA256()
	)
	print("Signature is valid.")
    
	# Verify the hash
	if original_message_hash == hashed_message:
        	print("Hashes match. Original message is intact.")
   	 
    	# Verify the timestamp
        	current_timestamp = datetime.datetime.now()
    	# Compare the extracted timestamp with the current timestamp or a predefined validity period
        	if current_timestamp - extracted_timestamp < datetime.timedelta(minutes=5):
                	print("Timestamp is valid.")
        	else:
                	print("Timestamp is invalid.", extracted_timestamp)
	else:
        	print("Hashes do not match. Original message may have been tampered with.")
except cryptography.exceptions.InvalidSignature:
	print("Signature is invalid.")