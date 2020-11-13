"""
Gives layer2 support for peer DIDs -- static DID docs. 30 min of coding to port.
"""

import base58  # Must use bitcoin's alphabet, not Flickr's.
import hashlib
import os
import re
import sys

# Use to detect whether a string is a valid peer DID. Parses into capture groups
# (1=numalgo, 2=base, 3=encnumbasis).
PEER_DID_PAT = re.compile(r'^did:peer:(1)(z)([1-9a-km-zA-HJ-NP-Z]{45})$')

# Where to store peer DIDs?
PEER_DID_STORAGE_FOLDER = os.path.expanduser('~/.peerdids')

DID_DOC_FILE_EXTENSION = '.diddoc'


def get_did_from_doc(stored_variant_did_doc_bytes):
    """
    Given the bytes of a stored variant of a genesis DID doc, get the corresponding DID.
    """

    # Optional fanciness not shown here:
    #
    # 1. Tolerate the resolved variant of a DID doc, and/or the DID doc passed in as a
    #    string instead of byte array, or as a python dict built by python's json module.
    # 2. Input validation (make sure DID doc is valid, incl requiring a key with the 'register'
    #    privilege).

    return 'did:peer:1z' + base58.b58encode(b'\x12' + hashlib.sha256(stored_variant_did_doc_bytes).digest()).decode(
        'ascii')


def save_did(stored_variant_did_doc_bytes):
    """
    Persists a peer DID doc to disk so it can be used to resolve the DID later. Throws on error.
    """
    fname = os.path.join(PEER_DID_STORAGE_FOLDER, get_did_from_doc(stored_variant_did_doc_bytes) + '.diddoc')

    # Optional fanciness not shown here:
    #
    # 1. Tolerate the resolved variant of a DID doc. (Detect it by checking for the presence of
    #    a top-level "id" property, and subtract it to get the stored variant.)
    # 2. Specify a different folder where DID docs are stored.
    # 3. Input validation (make sure DID doc is valid).

    with open(fname, 'wb') as f:
        f.write(stored_variant_did_doc_bytes)


def save_skey(key, filename):
    """
    Persists a signing key doc to disk so it can be used to verify, sign and encrypt messages later. Throws on error.
    """
    keyname = os.path.join(PEER_DID_STORAGE_FOLDER, filename)
    # Optional fanciness not shown here:
    #
    # 1. Tolerate the resolved variant of a DID doc. (Detect it by checking for the presence of
    #    a top-level "id" property, and subtract it to get the stored variant.)
    # 2. Specify a different folder where DID docs are stored.
    # 3. Input validation (make sure DID doc is valid).

    with open(keyname, 'wb') as f:
        f.write(key)


def resolve_did(did):
    """
    Given a peer DID, looks on disk to see if we have its DID doc. If yes, turns the on-disk, stored
    variant of the data into a resolved variant of a DID doc, and returns that variant as byte array.
    Returns None if DID is unknown. Throws on error.
    """

    # Optional fanciness not shown here:
    #
    # 1. Specify a different folder where DID docs are stored.
    # 2. Input validation (make sure DID value is valid).

    fname = os.path.join(PEER_DID_STORAGE_FOLDER, str(did) + '.diddoc')
    # print(fname)
    if os.path.isfile(fname):
        with open(fname, 'rb') as f:
            stored_variant_did_doc_bytes = f.read()
        i = stored_variant_did_doc_bytes.rfind('}'.encode())
        return stored_variant_did_doc_bytes  # + '"id": "%s"' % did + stored_variant_did_doc_bytes[i:]


# Dependencies for the following function.
import json
import sgl  # SGL defined on pypi and on npm; 200 lines of code to port for other langs


def is_authorized(privilege, did_doc, *keys):
    """
    Given a named privilege, a DID doc, and one or more keys, return True if the keys
    are collectively authorized to exercise the privilege. Throws on error.
    """
    parsed = json.loads(did_doc)

    # Find the profiles (assigned roles, like "edge" or "cloud") for each key.
    profiles = parsed['authorization']['profiles']
    defined_keys = []
    for k in keys:
        found = [p for p in profiles if p['id'] == k]
        if found:
            defined_keys.append(found[0])

    # Now look for rules that might grant the desired privilege.
    rules = parsed['authorization']['rules']
    for rule in rules:
        if privilege in rule['grant']:
            if sgl.satisfies(defined_keys, rule):
                return True
    return False


import ecdsa
import base64
import json


def sign(content_bytes, skey):
    return skey.sign(content_bytes)  # emit a JWS


def verify(content_bytes, vkey, jws):
    return vkey.verify(jws, content_bytes)


def connect(pthid, label, sig, diddoc, did):
    didcomm = {"@id": "5678876542345", "@type": "https://didcomm.org/didexchange/1.0/request",
               "~thread": {"pthid": "<id of invitation>"}, "label": "<Bob>", "connection": {"did": "<B.did@B:A>",
                                                                                            "did_doc~attach": {"data": {
                                                                                                "base64": "<base64 of exactly the bytes of DID doc from step 4>",
                                                                                                "sig": "<JWS of those bytes, signed by the key that controls the DID>"
                                                                                            }}}}
    # set pthid
    didcomm['~thread']['pthid'] = pthid
    # print(didcomm['~thread']['pthid'])
    # set label otherwise set to "blank"
    didcomm['label'] = label
    # print(didcomm['label'])
    # set did
    didcomm['connection']['did'] = did
    # print(didcomm['connection']['did'])
    # set base64 diddoc
    b64diddoc = base64.b64encode(diddoc.encode('ascii'))
    didcomm['connection']['did_doc~attach']['data']['base64'] = b64diddoc.decode()
    # print(didcomm['connection']['did_doc~attach']['data']['base64'])
    # set signature value
    didcomm['connection']['did_doc~attach']['data']['sig'] = sig
    # print(didcomm['connection']['did_doc~attach']['data']['sig'])
    # print(didcomm)
    return json.dumps(didcomm)


def set_diddoc(pubkey_hex, endpoint):
    diddoc = {"@context": "https://w3id.org/did/v1", "publicKey": ["<pub key in base64"],
              "service": [{"id": "default", "type": "didcomm", "serviceEndpoint": "<leogeo:A>"}]}

    # set public key value in hex format
    diddoc['publicKey'] = pubkey_hex
    # print(diddoc['publicKey'])
    # set service endpoint value
    diddoc['service'][0]['serviceEndpoint'] = endpoint
    # print(diddoc['service'][0]['serviceEndpoint'])
    return json.dumps(diddoc)


def keys_to_hex(vk):
    # return hex version of key
    return ecdsa.VerifyingKey.to_string().hex(vk)


def hex_to_keys(vk):
    # return normal version of key from hex
    return ecdsa.VerifyingKey.from_string(bytearray.fromhex(vk), curve=ecdsa.SECP256k1)


def verify_didcomm(didcomm_message_b64):
    # extract base64 encoded didcomm message
    # print(didcomm_message_b64)
    didcomm_message = base64.b64decode(didcomm_message_b64)
    didcomm_message_json = json.loads(didcomm_message.decode())
    # print(str(didcomm_message_json) + '\n')

    # extract diddoc
    diddocb64 = didcomm_message_json['connection']['did_doc~attach']['data']['base64']
    # print(diddocb64 + '\n')
    diddoc = base64.b64decode(diddocb64)
    diddoc_json = json.loads(diddoc.decode())
    # print(str(diddoc_json) +'\n')
    # extract public key from diddoc
    vk = diddoc_json['publicKey']
    # print(vk + '\n')
    vk1 = hex_to_keys(vk)
    # extract signature
    sig = didcomm_message_json['connection']['did_doc~attach']['data']['sig']
    # print(sig + '\n')
    # verify signature
    result = verify(diddoc, vk1, bytearray.fromhex(sig))
    print(
        'The verification of the diddoc, verify key and signature extracted from didcomm_message match result: {}'.format(
            result))
    return diddoc, vk1, sig, result


from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt


def icies_test(sk_hex, pk_hex, data):
    # assymtetric encryption/decryption test
    print(decrypt(sk_hex, encrypt(pk_hex, data)))
    secp_k = generate_key()
    sk_bytes = secp_k.secret  # bytes
    pk_bytes = secp_k.public_key.format(True)  # bytes
    print(decrypt(sk_bytes, encrypt(pk_bytes, data)))


def encrypt_message(sk_hex, pk_hex, data):
    # encrypt message
    encrypted_data = encrypt(pk_hex, data)
    return encrypted_data


def decrypt_message(sk_hex, pk_hex, data):
    # decrypt message
    decrypted_data = decrypt(sk_hex, data)
    return decrypted_data


def send_message(pthid, label, sig, encrypted_message, did):
    # to implement
    didcomm = {"@id": "5678876542345", "@type": "https://didcomm.org/didexchange/1.0/request",
               "~thread": {"pthid": "<id of invitation>"}, "label": "<Bob>", "connection": {"did": "<B.did@B:A>",
                                                                                            "message~attach": {"data": {
                                                                                                "base64": "<encrypted bytes of message>",
                                                                                                "sig": "<JWS of those bytes, signed by the key that controls the DID>"
                                                                                            }}}}
    # set pthid
    didcomm['~thread']['pthid'] = pthid
    # print(didcomm['~thread']['pthid'])
    # set label otherwise set to "blank"
    didcomm['label'] = label
    # print(didcomm['label'])
    # set did
    didcomm['connection']['did'] = did
    # print(didcomm['connection']['did'])
    # set base64 diddoc
    b64message = base64.b64encode(encrypted_message)
    didcomm['connection']['message~attach']['data']['base64'] = b64message.decode()
    # print(didcomm['connection']['message~attach']['data']['base64'])
    # set signature value
    didcomm['connection']['message~attach']['data']['sig'] = sig
    # print(didcomm['connection']['message~attach']['data']['sig'])
    # print(didcomm)
    return json.dumps(didcomm)


def verify_message(didcomm_message_b64):
    # extract base64 encoded didcomm message
    # print(didcomm_message_b64)
    didcomm_message = base64.b64decode(didcomm_message_b64)
    didcomm_message_json = json.loads(didcomm_message.decode())
    # print(str(didcomm_message_json) + '\n')

    # extract encrypted message
    didcommb64 = didcomm_message_json['connection']['message~attach']['data']['base64']
    # print('didcomm encrypted message base64: {}'.format(didcommb64 + '\n'))
    didcomm = base64.b64decode(didcommb64)
    # print('didcomm encrypted message base64 decoded: {}'.format(str(didcomm) + '\n'))

    # extract signature
    sig = didcomm_message_json['connection']['message~attach']['data']['sig']
    # print(sig + '\n')

    # extract did
    did = didcomm_message_json['connection']['did']
    # print(did + '\n')

    # lookup did document and get public key
    diddoc = resolve_did(did)
    # print(diddoc)
    diddoc_json = json.loads(diddoc.decode())

    # extract public key from diddoc
    vk = diddoc_json['publicKey']
    # print(vk + '\n')
    vk1 = hex_to_keys(vk)

    # verify signature
    result = verify(didcomm, vk1, bytearray.fromhex(sig))
    print(
        'The verification of the didcomm message result: {}'.format(
            result))
    return didcomm, vk1, sig, result

""" Data received from LEO TX"""
data = [
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
"""
data = [
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "WFl4TUdRaWZYMTlmUT09",
    "text": "XYxMGQifX19fQ==",
    "time": "2020-04-30T21:13:33.555028773Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TWV5SkFhV1FpT2lBaU5UWTNPRGczTmpVME1qTTBOU0lzSUNKQWRIbHdaU0k2SUNKb2RIUndjem92TDJScFpHTnZiVzB1YjNKbkwyUnBaR1Y0WTJoaGJtZGxMeg==",
    "text": "MeyJAaWQiOiAiNTY3ODg3NjU0MjM0NSIsICJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLz",
    "time": "2020-04-30T21:13:58.639598395Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "T1pXTjBhVzl1SWpvZ2V5SmthV1FpT2lBaVpHbGtPbkJsWlhJNk1YbzJZWGRoUVVveVJHRklZMkpoVW1sTmVqWkNaVVYyUkVnNU9VVXhNMjFHVlV0elFtNU1hVA==",
    "text": "OZWN0aW9uIjogeyJkaWQiOiAiZGlkOnBlZXI6MXo2YXdhQUoyRGFIY2JhUmlNejZCZUV2REg5OUUxM21GVUtzQm5MaT",
    "time": "2020-04-30T21:14:28.967227982Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UFJGYlU1VFkwNGlMQ0FpWkdsa1gyUnZZMzVoZEhSaFkyZ2lPaUI3SW1SaGRHRWlPaUI3SW1KaGMyVTJOQ0k2SUNKbGVVcEJXVEk1ZFdSSFZqUmtRMGsyU1VOSw==",
    "text": "PRFbU5TY04iLCAiZGlkX2RvY35hdHRhY2giOiB7ImRhdGEiOiB7ImJhc2U2NCI6ICJleUpBWTI5dWRHVjRkQ0k2SUNK",
    "time": "2020-04-30T21:14:39.123861954Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UWIyUklVbmRqZW05MlRETmplbUZYVVhWaU0wcHVUREpTY0ZwRE9USk5VMGx6U1VOS2QyUlhTbk5oVjA1TVdsaHJhVTlwUVdsT1YxbDRXbXBDYVU5VVp6TmFiVg==",
    "text": "Qb2RIUndjem92TDNjemFXUXViM0puTDJScFpDOTJNU0lzSUNKd2RXSnNhV05MWlhraU9pQWlOV1l4WmpCaU9UZzNabV",
    "time": "2020-04-30T21:14:59.276813567Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UkY2VFhwRmVVMXRXWGROZWtwcFdtMU5NRmxxVlROYVIwMTNUbnBzYkU5RVRtaE5SRmw1V2tkT2FVMUVhekJOVjFsNlRtMUpNRnB0VFROTmFrVTFUakpGZUU1WA==",
    "text": "RF6TXpFeU1tWXdNekppWm1NMFlqVTNaR013TnpsbE9ETmhNRFl5WkdOaU1EazBNV1l6Tm1JMFptTTNNakU1TjJFeE5X",
    "time": "2020-04-30T21:15:04.56000134Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "U1RYcE9lbHByV1ZSTmVscFVhR2xPUkVFMFdsZEpNbGw2UlhoWmFtY3dXVlJXYTAweVRtaE5la1pvV2xSR2FrMUhUbXhOYlVVeVdYcFZNbHBxV1hkWlZHZDZUaw==",
    "text": "STXpOelprWVRNelpUaGlOREE0WldJMll6RXhZamcwWVRWa00yTmhNekZoWlRGak1HTmxNbUUyWXpVMlpqWXdZVGd6Tk",
    "time": "2020-04-30T21:15:09.773065901Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TkV1TUM5eVpYRjFaWE4wSWl3Z0luNTBhSEpsWVdRaU9pQjdJbkIwYUdsa0lqb2dNWDBzSUNKc1lXSmxiQ0k2SUNKa2FXUTZlQzV3WldWeVFTSXNJQ0pqYjI1dQ==",
    "text": "NEuMC9yZXF1ZXN0IiwgIn50aHJlYWQiOiB7InB0aGlkIjogMX0sICJsYWJlbCI6ICJkaWQ6eC5wZWVyQSIsICJjb25u",
    "time": "2020-04-30T21:15:52.624611996Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VklzSUNKemFXY2lPaUFpTkRBMU1qZzRNR1F6T0dGaU56ZzVaVGhsT0RjNE56STNaamRsWTJNMU5EY3haRGhrTkRSaVltSmtZamRpT1RCa1pXUm1aalV6TlRCaw==",
    "text": "VIsICJzaWciOiAiNDA1Mjg4MGQzOGFiNzg5ZThlODc4NzI3ZjdlY2M1NDcxZDhkNDRiYmJkYjdiOTBkZWRmZjUzNTBk",
    "time": "2020-04-30T21:16:20.261644388Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "V1ltWTFNVFl6TVRVelkyWmhZMkk0TldKbU5EazFZems0TVdGbFptRXdORE0yTVdWaU9HRTFaVEE1WlRGalltRTJOamc1WldGbVpqVTVZMkl3TURZNU5qaGtOeg==",
    "text": "WYmY1MTYzMTUzY2ZhY2I4NWJmNDk1Yzk4MWFlZmEwNDM2MWViOGE1ZTA5ZTFjYmE2Njg5ZWFmZjU5Y2IwMDY5NjhkNz",
    "time": "2020-04-30T21:16:35.469974891Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "WFl4TUdRaWZYMTlmUT09",
    "text": "XYxMGQifX19fQ==",
    "time": "2020-04-30T21:16:35.546234805Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VGRSTWxwRVdtdE9WMGt4VGxST2ExbDZXbXRPVkZGcFRFTkJhV015Vm5sa2JXeHFXbE5KTmtsR2REZEpiV3hyU1dwdlowbHRVbXhhYlVZeFlraFJhVXhEUVdsaw==",
    "text": "TdRMlpEWmtOV0kxTlROa1l6WmtOVFFpTENBaWMyVnlkbWxqWlNJNklGdDdJbWxrSWpvZ0ltUmxabUYxYkhRaUxDQWlk",
    "time": "2020-04-30T21:16:52.710243467Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TkV1TUM5eVpYRjFaWE4wSWl3Z0luNTBhSEpsWVdRaU9pQjdJbkIwYUdsa0lqb2dNWDBzSUNKc1lXSmxiQ0k2SUNKa2FXUTZlQzV3WldWeVFTSXNJQ0pqYjI1dQ==",
    "text": "NEuMC9yZXF1ZXN0IiwgIn50aHJlYWQiOiB7InB0aGlkIjogMX0sICJsYWJlbCI6ICJkaWQ6eC5wZWVyQSIsICJjb25u",
    "time": "2020-04-30T21:17:20.876447057Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "T1pXTjBhVzl1SWpvZ2V5SmthV1FpT2lBaVpHbGtPbkJsWlhJNk1YbzJZWGRoUVVveVJHRklZMkpoVW1sTmVqWkNaVVYyUkVnNU9VVXhNMjFHVlV0elFtNU1hVA==",
    "text": "OZWN0aW9uIjogeyJkaWQiOiAiZGlkOnBlZXI6MXo2YXdhQUoyRGFIY2JhUmlNejZCZUV2REg5OUUxM21GVUtzQm5MaT",
    "time": "2020-04-30T21:17:31.135311547Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UFJGYlU1VFkwNGlMQ0FpWkdsa1gyUnZZMzVoZEhSaFkyZ2lPaUI3SW1SaGRHRWlPaUI3SW1KaGMyVTJOQ0k2SUNKbGVVcEJXVEk1ZFdSSFZqUmtRMGsyU1VOSw==",
    "text": "PRFbU5TY04iLCAiZGlkX2RvY35hdHRhY2giOiB7ImRhdGEiOiB7ImJhc2U2NCI6ICJleUpBWTI5dWRHVjRkQ0k2SUNK",
    "time": "2020-04-30T21:17:46.321932445Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VVNHeDNXbE5KTmtsRFNtdGhWMUpxWWpJeGRFbHBkMmRKYms1c1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWkpRMHB6V2xjNWJscFhPRFpSVTBvNVdGZ3dQUw==",
    "text": "USGx3WlNJNklDSmthV1JqYjIxdElpd2dJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJQ0pzWlc5blpXODZRU0o5WFgwPS",
    "time": "2020-04-30T21:17:52.47954378Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UWIyUklVbmRqZW05MlRETmplbUZYVVhWaU0wcHVUREpTY0ZwRE9USk5VMGx6U1VOS2QyUlhTbk5oVjA1TVdsaHJhVTlwUVdsT1YxbDRXbXBDYVU5VVp6TmFiVg==",
    "text": "Qb2RIUndjem92TDNjemFXUXViM0puTDJScFpDOTJNU0lzSUNKd2RXSnNhV05MWlhraU9pQWlOV1l4WmpCaU9UZzNabV",
    "time": "2020-04-30T21:18:01.432288929Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "UkY2VFhwRmVVMXRXWGROZWtwcFdtMU5NRmxxVlROYVIwMTNUbnBzYkU5RVRtaE5SRmw1V2tkT2FVMUVhekJOVjFsNlRtMUpNRnB0VFROTmFrVTFUakpGZUU1WA==",
    "text": "RF6TXpFeU1tWXdNekppWm1NMFlqVTNaR013TnpsbE9ETmhNRFl5WkdOaU1EazBNV1l6Tm1JMFptTTNNakU1TjJFeE5X",
    "time": "2020-04-30T21:18:26.648763775Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VVNHeDNXbE5KTmtsRFNtdGhWMUpxWWpJeGRFbHBkMmRKYms1c1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWkpRMHB6V2xjNWJscFhPRFpSVTBvNVdGZ3dQUw==",
    "text": "USGx3WlNJNklDSmthV1JqYjIxdElpd2dJbk5sY25acFkyVkZibVJ3YjJsdWRDSTZJQ0pzWlc5blpXODZRU0o5WFgwPS",
    "time": "2020-04-30T21:19:12.060742542Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "TWV5SkFhV1FpT2lBaU5UWTNPRGczTmpVME1qTTBOU0lzSUNKQWRIbHdaU0k2SUNKb2RIUndjem92TDJScFpHTnZiVzB1YjNKbkwyUnBaR1Y0WTJoaGJtZGxMeg==",
    "text": "MeyJAaWQiOiAiNTY3ODg3NjU0MjM0NSIsICJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL2RpZGV4Y2hhbmdlLz",
    "time": "2020-04-30T21:19:17.662887475Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VGRSTWxwRVdtdE9WMGt4VGxST2ExbDZXbXRPVkZGcFRFTkJhV015Vm5sa2JXeHFXbE5KTmtsR2REZEpiV3hyU1dwdlowbHRVbXhhYlVZeFlraFJhVXhEUVdsaw==",
    "text": "TdRMlpEWmtOV0kxTlROa1l6WmtOVFFpTENBaWMyVnlkbWxqWlNJNklGdDdJbWxrSWpvZ0ltUmxabUYxYkhRaUxDQWlk",
    "time": "2020-04-30T21:20:57.605216189Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "VklzSUNKemFXY2lPaUFpTkRBMU1qZzRNR1F6T0dGaU56ZzVaVGhsT0RjNE56STNaamRsWTJNMU5EY3haRGhrTkRSaVltSmtZamRpT1RCa1pXUm1aalV6TlRCaw==",
    "text": "VIsICJzaWciOiAiNDA1Mjg4MGQzOGFiNzg5ZThlODc4NzI3ZjdlY2M1NDcxZDhkNDRiYmJkYjdiOTBkZWRmZjUzNTBk",
    "time": "2020-04-30T21:21:02.722626232Z"
  },
  {
    "device_id": "bitlinq_lacunaspace_groundterminal2",
    "raw": "U1RYcE9lbHByV1ZSTmVscFVhR2xPUkVFMFdsZEpNbGw2UlhoWmFtY3dXVlJXYTAweVRtaE5la1pvV2xSR2FrMUhUbXhOYlVVeVdYcFZNbHBxV1hkWlZHZDZUaw==",
    "text": "STXpOelprWVRNelpUaGlOREE0WldJMll6RXhZamcwWVRWa00yTmhNekZoWlRGak1HTmxNbUUyWXpVMlpqWXdZVGd6Tk",
    "time": "2020-04-30T21:21:52.678902436Z"
  }
]
"""

counter = 0
index = set()
payloads = {}
base64_payload = ''
counter = 0
for row in data:
    # with 23 messages expected
    #print(ord(row['text'][0:1]) - 65 - 23)
    # with 12 messages expected
    #print(ord(row['text'][0:1]) - 65 - 12)
    message_number = ord(row['text'][0:1])
    if message_number not in payloads.keys():
      payloads[message_number] = {row['text'][1:]}
      # print(payloads)

    # if ord(row['text'][0:1]) - 65 - 12 >= counter:
    #   print(counter)
    #   base64+=row['text'][1:-1]
    #   counter+=1
    # #print(row['text'][1:-1])
    # # payloads["index"] = ord(row['text'][0:1]) - 65 - 12
    # # payloads["payload"] = row['text'][1:-1]
    # payloads.update([('index', ord(row['text'][0:1]) - 65 - 12), ('payload', row['text'][1:-1])])
    #index.add(ord(row['text'][0:1]) - 65 - 12)

#sorted(list, key=..., reverse=...)
# print(sorted(index))

# print(payloads.keys())
# print(payloads.values())
# print("\n")

# for key, payload in payloads.items():
#   print(payload)
# Creates a sorted dictionary (sorted by key)
from collections import OrderedDict
payloads_sorted = OrderedDict(sorted(payloads.items()))
for key,values in payloads_sorted.items():
    print("%s: %s" % (key, list(values)[0]))
    base64_payload += list(values)[0]

print("\n")

# print(base64_payload)
# print(base64.b64decode(base64_payload))
# diddoc = base64.b64decode(base64_payload)
# diddoc_json = json.loads(diddoc.decode())
# print(str(diddoc_json) + '\n')

# extract signature
# sig = diddoc_json['connection']['did_doc~attach']['data']['sig']
# print(sig)

"""Verify LEO TX received message"""

sk_encoded = b'NGQwYmQwZjNjZmZlYjI2YmE0NzJjNmZiNTk3M2M0ZDM4ZWViMzBlMTBmZWNlYmRiMWVhMzEwZjNiYWE2Y2Q3Yw=='
sk_decoded = base64.b64decode(sk_encoded.decode())
# print(sk_decoded)
# print(bytearray.fromhex(sk_decoded.decode()))

sk = ecdsa.SigningKey.from_string(bytearray.fromhex(sk_decoded.decode()),curve=ecdsa.SECP256k1)
# print(sk)
vk = sk.get_verifying_key()
# print(vk)

skB_encoded = b'YjMwMzM0Yzk0ZTEwNzNmMDViMWY1MmUwMzgyNTM2NDBhNDI3YTBhMjUxNWJiYTliYTVmMDg2YmQ3ODkxYmVhZQ===='
print('\n')
skB_decoded = base64.b64decode(skB_encoded.decode())
# print(skB_decoded)
# print(bytearray.fromhex(skB_decoded.decode()))

skB = ecdsa.SigningKey.from_string(bytearray.fromhex(skB_decoded.decode()),curve=ecdsa.SECP256k1)
# print(skB)
vkB = skB.get_verifying_key()
# print(vkB)

diddoc, vk, sig, result = verify_didcomm(base64_payload)
print(base64_payload)
print(diddoc)
verify(diddoc, vk, bytearray.fromhex(sig))


"""
diddoc = {"@context": "https://w3id.org/did/v1", "publicKey": "88c492ba974230d8a823270b2274927162aaa0675c04265b35484703ba5b078542fb0c0229a5d9484b5b930d8bbaf586c0e198d3227ddbfd9413d9f12904ee49", "service": [{"id": "default", "type": "didcomm", "serviceEndpoint": "leogeo:A"}]}

b'{"@context": "https://w3id.org/did/v1", "publicKey": "88c492ba974230d8a823270b2274927162aaa0675c04265b35484703ba5b078542fb0c0229a5d9484b5b930d8bbaf586c0e198d3227ddbfd9413d9f12904ee49", "service": [{"id": "default", "type": "didcomm", "serviceEndpoint": "leogeo:A"}]}'
"""