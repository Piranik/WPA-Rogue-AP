import pyshark
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

file = 'C:\Users\User\Desktop\multiHandshake-01.cap'

cap =  pyshark.FileCapture(file)

for pck in cap:
	protocols = pck.frame_info.get_field_value('protocols')
		
	
	if protocols == 'wlan:llc:eapol':	#eapol packet
		sourceMac = pck.wlan.get_field_value('sa')
		destinationMac = pck.wlan.get_field_value('da')
		
		pck.eapol.raw_mode = True
		#data for reconstruct raw layer
		data = 	\
			pck.eapol.version + \
			pck.eapol.type + \
			pck.eapol.len + \
			pck.eapol.keydes_type + \
			pck.eapol.wlan_rsna_keydes_key_info + \
			pck.eapol.keydes_key_len + \
			pck.eapol.keydes_replay_counter + \
			pck.eapol.wlan_rsna_keydes_nonce + \
			pck.eapol.keydes_key_iv + \
			pck.eapol.wlan_rsna_keydes_rsc + \
			pck.eapol.wlan_rsna_keydes_id + \
			pck.eapol.wlan_rsna_keydes_mic + \
			pck.eapol.wlan_rsna_keydes_data_len
		
		#print pck.eapol.wlan_rsna_keydes_data_len
		if pck.eapol.wlan_rsna_keydes_data_len != '0000':
			data += pck.eapol.wlan_rsna_keydes_data
		
		replayCounter = pck.eapol.keydes_replay_counter
		nonce = pck.eapol.wlan_rsna_keydes_nonce
		mic = pck.eapol.wlan_rsna_keydes_mic
		
		print data+"\n\n"
		
	elif protocols == 'wlan' and pck.wlan.fc == '0x00008000':	#beacon packet
		print pck.wlan.bssid + " " + pck.wlan_mgt.ssid
		
	
