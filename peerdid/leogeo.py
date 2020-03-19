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


# leogeo program flow
print('################ did:x.peerA ################' + '\n')
# generate key pair for did:x.peerA
# SECP256k1 is the Bitcoin elliptic curve
sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()

sk_hex = sk.to_string().hex()
# print(sk_hex)
vk_hex = vk.to_string().hex()
# print(vk_hex)

# generate diddoc for did:x.peerA
diddoc = set_diddoc(vk_hex, 'leogeo:A')
print('diddoc = {}'.format(diddoc + '\n'))

# save diddoc for did:x.peerA
save_did(bytes(diddoc.encode('ascii')))

# get did from saved diddoc
did = get_did_from_doc(bytes(diddoc.encode('ascii')))
# print(did)

# sign diddoc
# print(diddoc.encode())
diddocsig = sign(diddoc.encode(), sk)
diddocsig_hex = diddocsig.hex()

# generate invitation message
didcomm_message = connect(1, 'did:x.peerA', diddocsig_hex, diddoc, did)
print('didcomm_message = {}'.format(didcomm_message + '\n'))

didcomm_message_json = json.dumps(didcomm_message)
didcomm_message_b64 = base64.b64encode(didcomm_message.encode('ascii'))

# verify didcomm invitation message
diddoc, vk, sig, result = verify_didcomm(didcomm_message_b64)
verify(diddoc, vk, bytearray.fromhex(sig))

print('################ did:x.peerB ################' + '\n')
# generate did:x.peerB
# generate key pair for did:x.peerB
# SECP256k1 is the Bitcoin elliptic curve
skB = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
vkB = skB.get_verifying_key()

skB_hex = skB.to_string().hex()
# print(sk_hex)
vkB_hex = vkB.to_string().hex()
# print(vk_hex)

# generate diddoc for did:x.peerB
diddocB = set_diddoc(vkB_hex, 'leogeo:B')
print('diddoc = {}'.format(diddocB + '\n'))

# save diddoc for did:x.peerB
save_did(bytes(diddocB.encode('ascii')))

# get did from saved diddoc
didB = get_did_from_doc(bytes(diddocB.encode('ascii')))
# print(did)

# sign diddoc
# print(diddoc.encode())
diddocsigB = sign(diddocB.encode(), skB)
diddocsigB_hex = diddocsigB.hex()

# generate invitation response
didcomm_messageR = connect(1, 'did:x.peerB', diddocsigB_hex, diddocB, didB)
print('didcomm_message = {}'.format(didcomm_messageR + '\n'))

didcomm_messageR_json = json.dumps(didcomm_messageR)
didcomm_messageR_b64 = base64.b64encode(didcomm_messageR.encode('ascii'))

# verify didcomm invitation response message
diddocR, vkR, sigR, resultR = verify_didcomm(didcomm_messageR_b64)
verify(diddocR, vkR, bytearray.fromhex(sigR))

print('################ did:x.peerA message to did:x.peerB ################' + '\n')
print('plaintext message to encrypt - {}'.format(b'hello world!'))
epayload = encrypt_message(sk_hex, vkB_hex, b'hello world!')

b64_epayload = base64.b64encode(epayload)
print('base64 encrypted payload tx: {}'.format(b64_epayload))
b64_epayload_sig = sign(b64_epayload, skB)
db64_epayload_sig_hex = b64_epayload_sig.hex()
# print('encrypted base64 payload signature: {}'.format(db64_epayload_sig_hex))

encrypted_didcomm = send_message(1, 'test', db64_epayload_sig_hex, b64_epayload, didB)
print('encrypted data payload in didcomm format - {}'.format(encrypted_didcomm))

didcommb64, vk1, sig, result = verify_message(base64.b64encode(encrypted_didcomm.encode()))

print('base64 encrypted payload rx: {}'.format(didcommb64))
dpayload = decrypt_message(skB_hex, vk_hex, base64.b64decode(didcommb64))
print('decrypted message received from peer DID - {}\n'.format(dpayload))

# send message over LEO to TTN network
# copy and paste base64 output onto LEO terminal and schedule to transmit

# listen for messages arriving on TTN network

# fetch MQTT messages and verify DID document and signature

# send diddoc response

# verify diddoc response received

# craft encrypted message from LEO

# repeat
