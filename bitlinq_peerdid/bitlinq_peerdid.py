import base64
import json
import os
import configargparse
from datetime import datetime
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
print(str(datetime.now()) + ": Starting the Bitlinq message handler - version " + str(bitlinq.version))
bitlinq.system_checks()

mqttc = bitlinq.connect_mqtt()

# Assign event callbacks

# mqttc.on_connect = bitlinq.on_connect

# mqttc.on_message = bitlinq.on_message

# Log all MQTT protocol events and exceptions in callbacks

mqttc.on_log = bitlinq.on_log

# Subscribe to messages
bitlinq.subscribe(mqttc)

header = "Bitlinq message handler - DID mode -v" + str(bitlinq.version) + "| "
footer = " | Brought to you by www.bitlinq.space - 2020"
n_messages = 0
teller = 0
msats = 0
sent_messages = set()
n_space_messages = 0

""" Data received from LEO TX"""
TTN_test_data = [
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TWFVMUVhekJOVjFsNlRtMUpNRnB0VFROTmFrVTFUakpGZUU1WFRYcE9lbHByV1ZSTmVscFVhR2xPUkVFMFdsZEpNbGw2UlhoWmFtY3dXVlJXYTAweVRtaE5la1pvV2xSR2FrMUhUbXhOYlVVeVdYcFZNbHBxV1hkWlZHZDZUaw==",
    "text": "MaU1EazBNV1l6Tm1JMFptTTNNakU1TjJFeE5XTXpOelprWVRNelpUaGlOREE0WldJMll6RXhZamcwWVRWa00yTmhNekZoWlRGak1HTmxNbUUyWXpVMlpqWXdZVGd6Tk",
    "time": "2020-05-03T21:22:29.682809979Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UGRpT1RCa1pXUm1aalV6TlRCa1ltWTFNVFl6TVRVelkyWmhZMkk0TldKbU5EazFZems0TVdGbFptRXdORE0yTVdWaU9HRTFaVEE1WlRGalltRTJOamc1WldGbVpqVTVZMkl3TURZNU5qaGtOell4TUdRaWZYMTlmUT09",
    "text": "PdiOTBkZWRmZjUzNTBkYmY1MTYzMTUzY2ZhY2I4NWJmNDk1Yzk4MWFlZmEwNDM2MWViOGE1ZTA5ZTFjYmE2Njg5ZWFmZjU5Y2IwMDY5NjhkNzYxMGQifX19fQ==",
    "time": "2020-05-03T21:23:10.243874527Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "SWV5SkFhV1FpT2lBaU5UWTNPRGczTmpVME1qTTBOU0lzSUNKQWRIbHdaU0k2SUNKb2RIUndjem92TDJScFpHTnZiVzB1YjNKbkwyUnBaR1Y0WTJoaGJtZGxMekV1TUM5eVpYRjFaWE4wSWl3Z0luNTBhSEpsWVdRaU9pQjdJbg==",
    "text": "IeyJAaWQiOiAiNTY3ODg3NjU0MjM0NSIsICJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMC9yZXF1ZXN0IiwgIn50aHJlYWQiOiB7In",
    "time": "2020-05-03T21:23:15.555376127Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "S09VVXhNMjFHVlV0elFtNU1hVFJGYlU1VFkwNGlMQ0FpWkdsa1gyUnZZMzVoZEhSaFkyZ2lPaUI3SW1SaGRHRWlPaUI3SW1KaGMyVTJOQ0k2SUNKbGVVcEJXVEk1ZFdSSFZqUmtRMGsyU1VOS2IyUklVbmRqZW05MlRETmplbQ==",
    "text": "KOUUxM21GVUtzQm5MaTRFbU5TY04iLCAiZGlkX2RvY35hdHRhY2giOiB7ImRhdGEiOiB7ImJhc2U2NCI6ICJleUpBWTI5dWRHVjRkQ0k2SUNKb2RIUndjem92TDNjem",
    "time": "2020-05-03T21:23:25.980577202Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TEZYVVhWaU0wcHVUREpTY0ZwRE9USk5VMGx6U1VOS2QyUlhTbk5oVjA1TVdsaHJhVTlwUVdsT1YxbDRXbXBDYVU5VVp6TmFiVkY2VFhwRmVVMXRXWGROZWtwcFdtMU5NRmxxVlROYVIwMTNUbnBzYkU5RVRtaE5SRmw1V2tkTw==",
    "text": "LFXUXViM0puTDJScFpDOTJNU0lzSUNKd2RXSnNhV05MWlhraU9pQWlOV1l4WmpCaU9UZzNabVF6TXpFeU1tWXdNekppWm1NMFlqVTNaR013TnpsbE9ETmhNRFl5WkdO",
    "time": "2020-05-03T21:23:31.19851129Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TWFVMUVhekJOVjFsNlRtMUpNRnB0VFROTmFrVTFUakpGZUU1WFRYcE9lbHByV1ZSTmVscFVhR2xPUkVFMFdsZEpNbGw2UlhoWmFtY3dXVlJXYTAweVRtaE5la1pvV2xSR2FrMUhUbXhOYlVVeVdYcFZNbHBxV1hkWlZHZDZUaw==",
    "text": "MaU1EazBNV1l6Tm1JMFptTTNNakU1TjJFeE5XTXpOelprWVRNelpUaGlOREE0WldJMll6RXhZamcwWVRWa00yTmhNekZoWlRGak1HTmxNbUUyWXpVMlpqWXdZVGd6Tk",
    "time": "2020-05-03T21:23:31.404803517Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TmRSTWxwRVdtdE9WMGt4VGxST2ExbDZXbXRPVkZGcFRFTkJhV015Vm5sa2JXeHFXbE5KTmtsR2REZEpiV3hyU1dwdlowbHRVbXhhYlVZeFlraFJhVXhEUVdsa1NHeDNXbE5KTmtsRFNtdGhWMUpxWWpJeGRFbHBkMmRKYms1cw==",
    "text": "NdRMlpEWmtOV0kxTlROa1l6WmtOVFFpTENBaWMyVnlkbWxqWlNJNklGdDdJbWxrSWpvZ0ltUmxabUYxYkhRaUxDQWlkSGx3WlNJNklDSmthV1JqYjIxdElpd2dJbk5s",
    "time": "2020-05-03T21:23:31.624254546Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "T1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWkpRMHB6V2xjNWJscFhPRFpSVTBvNVdGZ3dQU0lzSUNKemFXY2lPaUFpTkRBMU1qZzRNR1F6T0dGaU56ZzVaVGhsT0RjNE56STNaamRsWTJNMU5EY3haRGhrTkRSaVltSmtZag==",
    "text": "OY25acFkyVkZibVJ3YjJsdWRDSTZJQ0pzWlc5blpXODZRU0o5WFgwPSIsICJzaWciOiAiNDA1Mjg4MGQzOGFiNzg5ZThlODc4NzI3ZjdlY2M1NDcxZDhkNDRiYmJkYj",
    "time": "2020-05-03T21:23:41.824340491Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UGRpT1RCa1pXUm1aalV6TlRCa1ltWTFNVFl6TVRVelkyWmhZMkk0TldKbU5EazFZems0TVdGbFptRXdORE0yTVdWaU9HRTFaVEE1WlRGalltRTJOamc1WldGbVpqVTVZMkl3TURZNU5qaGtOell4TUdRaWZYMTlmUT09",
    "text": "PdiOTBkZWRmZjUzNTBkYmY1MTYzMTUzY2ZhY2I4NWJmNDk1Yzk4MWFlZmEwNDM2MWViOGE1ZTA5ZTFjYmE2Njg5ZWFmZjU5Y2IwMDY5NjhkNzYxMGQifX19fQ==",
    "time": "2020-05-03T21:23:42.108594628Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "SWV5SkFhV1FpT2lBaU5UWTNPRGczTmpVME1qTTBOU0lzSUNKQWRIbHdaU0k2SUNKb2RIUndjem92TDJScFpHTnZiVzB1YjNKbkwyUnBaR1Y0WTJoaGJtZGxMekV1TUM5eVpYRjFaWE4wSWl3Z0luNTBhSEpsWVdRaU9pQjdJbg==",
    "text": "IeyJAaWQiOiAiNTY3ODg3NjU0MjM0NSIsICJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLzEuMC9yZXF1ZXN0IiwgIn50aHJlYWQiOiB7In",
    "time": "2020-05-03T21:24:07.319145352Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "SkIwYUdsa0lqb2dNWDBzSUNKc1lXSmxiQ0k2SUNKa2FXUTZlQzV3WldWeVFTSXNJQ0pqYjI1dVpXTjBhVzl1SWpvZ2V5SmthV1FpT2lBaVpHbGtPbkJsWlhJNk1YbzJZWGRoUVVveVJHRklZMkpoVW1sTmVqWkNaVVYyUkVnNQ==",
    "text": "JB0aGlkIjogMX0sICJsYWJlbCI6ICJkaWQ6eC5wZWVyQSIsICJjb25uZWN0aW9uIjogeyJkaWQiOiAiZGlkOnBlZXI6MXo2YXdhQUoyRGFIY2JhUmlNejZCZUV2REg5",
    "time": "2020-05-03T21:24:52.699606236Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "T1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWkpRMHB6V2xjNWJscFhPRFpSVTBvNVdGZ3dQU0lzSUNKemFXY2lPaUFpTkRBMU1qZzRNR1F6T0dGaU56ZzVaVGhsT0RjNE56STNaamRsWTJNMU5EY3haRGhrTkRSaVltSmtZag==",
    "text": "OY25acFkyVkZibVJ3YjJsdWRDSTZJQ0pzWlc5blpXODZRU0o5WFgwPSIsICJzaWciOiAiNDA1Mjg4MGQzOGFiNzg5ZThlODc4NzI3ZjdlY2M1NDcxZDhkNDRiYmJkYj",
    "time": "2020-05-03T21:24:52.870849958Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TEZYVVhWaU0wcHVUREpTY0ZwRE9USk5VMGx6U1VOS2QyUlhTbk5oVjA1TVdsaHJhVTlwUVdsT1YxbDRXbXBDYVU5VVp6TmFiVkY2VFhwRmVVMXRXWGROZWtwcFdtMU5NRmxxVlROYVIwMTNUbnBzYkU5RVRtaE5SRmw1V2tkTw==",
    "text": "LFXUXViM0puTDJScFpDOTJNU0lzSUNKd2RXSnNhV05MWlhraU9pQWlOV1l4WmpCaU9UZzNabVF6TXpFeU1tWXdNekppWm1NMFlqVTNaR013TnpsbE9ETmhNRFl5WkdO",
    "time": "2020-05-03T21:25:13.086620624Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "S09VVXhNMjFHVlV0elFtNU1hVFJGYlU1VFkwNGlMQ0FpWkdsa1gyUnZZMzVoZEhSaFkyZ2lPaUI3SW1SaGRHRWlPaUI3SW1KaGMyVTJOQ0k2SUNKbGVVcEJXVEk1ZFdSSFZqUmtRMGsyU1VOS2IyUklVbmRqZW05MlRETmplbQ==",
    "text": "KOUUxM21GVUtzQm5MaTRFbU5TY04iLCAiZGlkX2RvY35hdHRhY2giOiB7ImRhdGEiOiB7ImJhc2U2NCI6ICJleUpBWTI5dWRHVjRkQ0k2SUNKb2RIUndjem92TDNjem",
    "time": "2020-05-03T21:26:02.987022803Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "SkIwYUdsa0lqb2dNWDBzSUNKc1lXSmxiQ0k2SUNKa2FXUTZlQzV3WldWeVFTSXNJQ0pqYjI1dVpXTjBhVzl1SWpvZ2V5SmthV1FpT2lBaVpHbGtPbkJsWlhJNk1YbzJZWGRoUVVveVJHRklZMkpoVW1sTmVqWkNaVVYyUkVnNQ==",
    "text": "JB0aGlkIjogMX0sICJsYWJlbCI6ICJkaWQ6eC5wZWVyQSIsICJjb25uZWN0aW9uIjogeyJkaWQiOiAiZGlkOnBlZXI6MXo2YXdhQUoyRGFIY2JhUmlNejZCZUV2REg5",
    "time": "2020-05-03T21:26:03.173565028Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TWFVMUVhekJOVjFsNlRtMUpNRnB0VFROTmFrVTFUakpGZUU1WFRYcE9lbHByV1ZSTmVscFVhR2xPUkVFMFdsZEpNbGw2UlhoWmFtY3dXVlJXYTAweVRtaE5la1pvV2xSR2FrMUhUbXhOYlVVeVdYcFZNbHBxV1hkWlZHZDZUaw==",
    "text": "MaU1EazBNV1l6Tm1JMFptTTNNakU1TjJFeE5XTXpOelprWVRNelpUaGlOREE0WldJMll6RXhZamcwWVRWa00yTmhNekZoWlRGak1HTmxNbUUyWXpVMlpqWXdZVGd6Tk",
    "time": "2020-05-03T21:26:52.606369045Z"
  }
]

bitlinq.messages = TTN_test_data
# print(bitlinq.messages)
try:
    # Listen to server
    mqttc.loop_start()

    # Main loop
    while True:
        print(str(datetime.now()) + ": V" + str(bitlinq.version) + " - Waiting for data.. " + str(
            len(sent_messages)) + " messages (of which " + str(
            n_space_messages) + " messages from Space) relayed so far (limit=" + str(bitlinq.limit_sentmessages) + ")")
        print(str(datetime.now()) + ": Total cost is: " + str(msats) + " millisatoshis. ")
        print(str(datetime.now()) + ": mode=" + bitlinq.mode[bitlinq.test])
        n_messages = len(bitlinq.messages)
        if n_messages != 0:
            incoming_base64_payload = bitlinq.repack_messages(bitlinq.messages)
            print(base64.b64decode(incoming_base64_payload))
            # verify didcomm invitation message
            diddocV, vk, sig, result = leogeo_did2.verify_didcomm(incoming_base64_payload)
            leogeo_did1.verify(diddocV, vk, bytearray.fromhex(sig))
            # messages2 = []
            # messages2.append(bitlinq.messages[0])
            # print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\n')
            # print(messages2)
            if bitlinq.timeformat == 1:
                start = 11
                stop = 28
                data = dict(bitlinq.messages[0])
                # print('DATA={} DATALEN {}'.format(data, len(data)))
                timedata = data['time'][:-4]
                timesent = datetime.strptime(timedata, '%Y-%m-%dT%H:%M:%S.%f')
                # print(timesent)
                timenow = datetime.now()
                print(str('{}: Time when message was sent Normal time: {} Unix time: {}'.format(datetime.now(), str(timesent),str(timesent.timestamp()))))
                print(str('{}: Time when message was received Normal time: {} Unix time: {}'.format(datetime.now(), str(timenow),str(timenow.timestamp()))))
                print(str(datetime.now()) + ": Latency of message=" + str(
                    (timenow.timestamp() - timesent.timestamp()) / 60) + " minutes")

            for item in bitlinq.messages:
                message2 = header + item['text'] + footer
                print(str(datetime.now()) + ": Message:" + message2)
                if message2 in sent_messages:
                    print(str(datetime.now()) + ": Message already sent before")
                else:
                    # TODO remove static gateway assignment below for production
                    bitlinq.gateway_ID.append(TTN_GATEWAY_ID_LS1)
                    print(str(datetime.now()) + ": Gateway ID: " + bitlinq.gateway_ID[0])
                    if bitlinq.gateway_ID[0] == TTN_GATEWAY_ID_LS1:
                        print(str(
                            datetime.now()) + ": Message received from Lacuna Space LS1 payload on-board M6P satellite!!!")
                        n_space_messages = n_space_messages + 1
                    # TODO remove disabling of Blockstream LN message sending
                    # msats = msats + bitlinq.send_pay(message2)
                    text = "Message sent to Blockstream API" + ": " + message2 + ", Latency of message=" + str(
                        (timenow.timestamp() - timesent.timestamp()) / 60) + " minutes, gatewayID=" + bitlinq.gateway_ID[0]
                    # print(text)
                    # print(bitlinq.telegram_bot_sendtext(str(didcomm_messageR_b64.decode())))
                    response = bitlinq.telegram_bot_sendtext(text)
                    print('\nTELGRAM HTTP Post Response: {}\n'.format(response))
                    print(str(datetime.now()) + ": " + text + " (with copy to Telegram)")
                    sent_messages.add(message2)
                    if len(sent_messages) >= bitlinq.limit_sentmessages:
                        mqttc.loop_stop()
                        print(str(datetime.now()) + ": Stopped after relaying " + str(
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