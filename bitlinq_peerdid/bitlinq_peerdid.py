import base64
import json
import os
import configargparse
import datetime
import sys
import time

from bitlinq import BitlinqAPI
from leogeo_didcomm import LeoGeoDID
from dotenv import load_dotenv, find_dotenv



# automatically find and load the .env file
load_dotenv(find_dotenv())

# p = configargparse.get_argument_parser()
# p.add('-m', '--mode', required=True, help='Define the operational mode. 1:testing option on, 0:operational mode on.')
# p.add('-ts', '--timestep', required=True, help='Define the timestep duration.')
# p.add('-mc', '--message-count', required=True, help='Define the number of messages to send.')
# p.add('-tf', '--time-format', required=True, help='Define the timeformat. # 1:timeformat part of message, 0: timeformat is not part of message.')
# p.add('-m', '--message', required=True, help='Define the message to be send via Blockstream satellite')
# p.add('-bm', '--telegram-message', required=True, help='Define the message to be send via Blockstream Telegram channel.')
# p.add('-v', help='verbose', action='store_true')
# options = p.parse_args()
#
# print(options)
# print("----------")
# print(p.format_help())
# print("----------")
# print(p.format_values())    # useful for logging where different settings came from

# Load sensitive info from environment variables
BOT_TOKEN = os.environ.get("BOT_TOKEN")
BOT_CHATID = os.environ.get("BOT_CHATID")
TTN_GATEWAY_ID_LS1 = os.environ.get("GATEWAY_ID_LS1")
TTN_USERNAME = os.environ.get("USERNAME")
TTN_PASSWORD = os.environ.get("PASSWORD")
TTN_HOSTNAME = os.environ.get("HOSTNAME")
TTN_PORT = os.environ.get("PORT")

# leogeo program flow
print('################ INITIALISE ################' + '\n')

bitlinq = BitlinqAPI(TTN_USERNAME, TTN_PASSWORD, TTN_HOSTNAME, TTN_PORT, BOT_TOKEN, BOT_CHATID)
leogeo_did1 = LeoGeoDID(1)
leogeo_did2 = LeoGeoDID(1)

# Generate key pairs
leogeo_did1.generate_ecdsa_key()
leogeo_did2.generate_ecdsa_key()

# save private and public keys in hex format
leogeo_did1.save_keys('leogeo1')
leogeo_did2.save_keys('leogeo2')
# generate diddoc for did:x.peerA
diddoc1 = leogeo_did1.set_diddoc('leogeo1:A')
diddoc2 = leogeo_did2.set_diddoc('leogeo2:A')
# print('diddoc = {}'.format(diddoc + '\n'))

# save the diddoc
leogeo_did1.save_did(diddoc1)
leogeo_did2.save_did(diddoc2)

# get dids from saved diddoc
did1 = leogeo_did1.get_did_from_doc(bytes(diddoc1.encode('ascii')))
did2 = leogeo_did2.get_did_from_doc(bytes(diddoc2.encode('ascii')))
print(did1,did2)

# sign diddoc
diddocsig1 = leogeo_did1.sign(diddoc1.encode())
diddocsig_hex1 = diddocsig1.hex()

diddocsig2 = leogeo_did2.sign(diddoc2.encode())
diddocsig_hex2 = diddocsig2.hex()

print('################ bitlinq_peerdid establish connection ################' + '\n')

# generate invitation message
didcomm_message1 = leogeo_did1.connect(1, 'did:x.peerA', diddocsig_hex1, diddoc1, did1)
print('didcomm_message = {}'.format(didcomm_message1 + '\n'))

didcomm_message_json = json.dumps(didcomm_message1)
didcomm_message_b64 = base64.b64encode(didcomm_message1.encode('ascii'))

print('base64 encoded message for LEO to send to TTN\n{}\n'.format(didcomm_message_b64))

# copy and paste base64 output onto LEO terminal and schedule to transmit

# send message over LEO to TTN network

# fetch MQTT messages and verify DID document and signature
# verify didcomm invitation message
diddocV, vk, sig, result = leogeo_did2.verify_didcomm(didcomm_message_b64)
leogeo_did1.verify(diddocV, vk, bytearray.fromhex(sig))

# generate invitation response
didcomm_messageR = leogeo_did2.connect(1, 'did:x.peerB', diddocsig_hex2, diddoc2, did2)
print('didcomm_message = {}'.format(didcomm_messageR + '\n'))

didcomm_messageR_json = json.dumps(didcomm_messageR)
didcomm_messageR_b64 = base64.b64encode(didcomm_messageR.encode('ascii'))

print('base64 encoded message response from TTN to Blockstream API back to LEO\n{}\n'.format(didcomm_messageR_b64))

# TODO Move below code to after TTN messages are received
#################### MOVE TO AFTER TTN MESSAGES RECEIVED ####################
# verify didcomm invitation response message
diddocR, vkR, sigR, resultR = leogeo_did1.verify_didcomm(didcomm_messageR_b64)
leogeo_did2.verify(diddocR, vkR, bytearray.fromhex(sigR))

print('################ bitlinq_peerdid establish messaging ################' + '\n')
print('plaintext message to encrypt - {}'.format(b'hello world!'))
epayload = leogeo_did1.encrypt_message(leogeo_did1.sk_hex, leogeo_did2.vk_hex, b'hello world!')

b64_epayload = base64.b64encode(epayload)
print('base64 encrypted payload tx: {}'.format(b64_epayload))
b64_epayload_sig = leogeo_did2.sign(b64_epayload)
db64_epayload_sig_hex = b64_epayload_sig.hex()
# print('encrypted base64 payload signature: {}'.format(db64_epayload_sig_hex))

encrypted_didcomm = leogeo_did1.send_message(1, 'test', db64_epayload_sig_hex, b64_epayload, did2)
print('encrypted data payload in didcomm format - {}'.format(encrypted_didcomm))

didcommb64, vk1, sig, result = leogeo_did1.verify_message(base64.b64encode(encrypted_didcomm.encode()))

print('base64 encrypted payload rx: {}'.format(didcommb64))
dpayload = leogeo_did2.decrypt_message(leogeo_did2.sk_hex, leogeo_did1.vk_hex, base64.b64decode(didcommb64))
print('decrypted message received from peer DID - {}\n'.format(dpayload))

#################### MOVE TO AFTER TTN MESSAGES RECEIVED ####################

# listen for messages arriving on TTN network
print(str(datetime.datetime.now()) + ": Starting the Bitlinq message handler - version " + str(bitlinq.version))
bitlinq.system_checks()

mqttc = bitlinq.connect_mqtt()

# Assign event callbacks

# mqttc.on_connect = bitlinq.on_connect

# mqttc.on_message = bitlinq.on_message

# Log all MQTT protocol events and exceptions in callbacks

mqttc.on_log = bitlinq.on_log

# Subscribe to messages
bitlinq.subscribe(mqttc)

header = "Bitlinq message handler - PGP P2P mode -v" + str(bitlinq.version) + "| "
footer = " | Brought to you by www.bitlinq.space - 2020"
n_messages = 0
teller = 0
msats = 0
sent_messages = set()
n_space_messages = 0

try:
    # Listen to server
    mqttc.loop_start()

    # Main loop
    while True:
        print(str(datetime.datetime.now()) + ": V" + str(bitlinq.version) + " - Waiting for data.. " + str(
            len(sent_messages)) + " messages (of which " + str(
            n_space_messages) + " messages from Space) relayed so far (limit=" + str(bitlinq.limit_sentmessages) + ")")
        print(str(datetime.datetime.now()) + ": Total cost is: " + str(msats) + " millisatoshis. ")
        print(str(datetime.datetime.now()) + ": mode=" + bitlinq.mode[bitlinq.test])
        n_messages = len(bitlinq.messages)
        if n_messages != 0:
            messages2 = []
            messages2.append(bitlinq.messages[0])
            if bitlinq.timeformat == 1:
                start = 2
                stop = 12
                data = str(bitlinq.messages[0])
                timesent = int(data[start:stop])  # seconds since January 1, 1970
                timenow = int(time.time())
                print(str(datetime.datetime.now()) + ": Time when message was sent (Unix time):" + str(timesent))
                print(str(datetime.datetime.now()) + ": Time when message was received (Unix time):" + str(timenow))
                print(str(datetime.datetime.now()) + ": Latency of message=" + str(
                    (timenow - timesent) / 60) + " minutes")
            for i in range(1, n_messages):
                if bitlinq.messages[i] != messages[i - 1]:
                    messages2.append(messages[i])
            message2 = header + '\n' + '\n'.join(messages2) + '\n' + footer
            print(str(datetime.datetime.now()) + ": Message:" + message2)
            if message2 in sent_messages:
                print(str(datetime.datetime.now()) + ": Message already sent before")
            else:
                print(str(datetime.datetime.now()) + ": Gateway ID: " + bitlinq.gateway_ID[0])
                if bitlinq.gateway_ID[0] == TTN_GATEWAY_ID_LS1:
                    print(str(
                        datetime.datetime.now()) + ": Message received from Lacuna Space LS1 payload on-board M6P satellite!!!")
                    n_space_messages = n_space_messages + 1
                msats = msats + bitlinq.send_pay(message2)
                text = "Message sent to Blockstream API"
                bitlinq.telegram_bot_sendtext(text + ": " + message2 + ", Latency of message=" + str(
                    (timenow - timesent) / 60) + " minutes, gateway_ID=" + bitlinq.gateway_ID[0])
                print(str(datetime.datetime.now()) + ": " + text + " (with copy to Telegram)")
                sent_messages.add(message2)
                if len(sent_messages) >= bitlinq.limit_sentmessages:
                    mqttc.loop_stop()
                    print(str(datetime.datetime.now()) + ": Stopped after relaying " + str(
                        bitlinq.limit_sentmessages) + " messages")
                    sys.exit()
            messages = []
            gateway_ID = []
        time.sleep(bitlinq.timestep)

except KeyboardInterrupt:
    print('\n' + "Interrupted by Keyboard (ctrl-C)")
    mqttc.loop_stop()

# send diddoc response

# verify diddoc response received

# craft encrypted message from LEO

# repeat