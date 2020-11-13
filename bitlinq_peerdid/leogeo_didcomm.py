"""
Gives layer2 support for peer DIDs -- static DID docs. 30 min of coding to port.
"""

import base58  # Must use bitcoin's alphabet, not Flickr's.
import hashlib
import os
import re
import sys
import ecdsa
import base64
import json
import sgl  # SGL defined on pypi and on npm; 200 lines of code to port for other langs
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import pickle

# Use to detect whether a string is a valid peer DID. Parses into capture groups
# (1=numalgo, 2=base, 3=encnumbasis).
PEER_DID_PAT = re.compile(r'^did:peer:(1)(z)([1-9a-km-zA-HJ-NP-Z]{45})$')

# Where to store peer DIDs?
PEER_DID_STORAGE_FOLDER = os.path.expanduser('~/.peerdids')

DID_DOC_FILE_EXTENSION = '.diddoc'


class LeoGeoDID:
    def __init__(self, did):#, did_doc, key, filename, content_bytes, privilege, stored_variant_did_doc_bytes):
        self.did = did
        # self.stored_variant_did_doc_bytes = stored_variant_did_doc_bytes
        # self.filename = filename
        # self.privilege = privilege
        # self.did_doc = did_doc
        # self.sk = ecdsa.SigningKey
        # self.vk = ecdsa.keys.VerifyingKey
        # self.sk_hex = None
        # self.vk_hex = None
        # diddoc
        # self.content_bytes = content_bytes
        # jws
        # pthid
        # label
        # sig
        # pubkey_hex
        # endpoint
        # didcomm_message_b64
        # encrypted_message

    def generate_ecdsa_key(self):
        """
        Given the bytes of a stored variant of a genesis DID doc, get the corresponding DID.
        """

        # Optional fanciness not shown here:
        #
        # 1. Tolerate the resolved variant of a DID doc, and/or the DID doc passed in as a
        #    string instead of byte array, or as a python dict built by python's json module.
        # 2. Input validation (make sure DID doc is valid, incl requiring a key with the 'register'
        #    privilege).

        self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.vk = self.sk.get_verifying_key()

        self.sk_hex = self.sk.to_string().hex()
        # print(sk_hex)
        self.vk_hex = self.vk.to_string().hex()
        # print(vk_hex)

        return self.sk, self.vk, self.sk_hex, self.vk_hex


    def get_did_from_doc(self, stored_variant_did_doc_bytes):
        """
        Given the bytes of a stored variant of a genesis DID doc, get the corresponding DID.
        """

        # Optional fanciness not shown here:
        #
        # 1. Tolerate the resolved variant of a DID doc, and/or the DID doc passed in as a
        #    string instead of byte array, or as a python dict built by python's json module.
        # 2. Input validation (make sure DID doc is valid, incl requiring a key with the 'register'
        #    privilege).

        return 'did:peer:1z' + base58.b58encode(b'\x12' + hashlib.sha256(stored_variant_did_doc_bytes).digest()).decode('ascii')

    def save_did(self, stored_variant_did_doc_bytes):
        """
        Persists a peer DID doc to disk so it can be used to resolve the DID later. Throws on error.
        """
        # TODO Fix the stored v
        fname = os.path.join(PEER_DID_STORAGE_FOLDER, self.get_did_from_doc(str(stored_variant_did_doc_bytes).encode('utf-8')) + '.diddoc')

        # Optional fanciness not shown here:
        #
        # 1. Tolerate the resolved variant of a DID doc. (Detect it by checking for the presence of
        #    a top-level "id" property, and subtract it to get the stored variant.)
        # 2. Specify a different folder where DID docs are stored.
        # 3. Input validation (make sure DID doc is valid).

        with open(fname, 'wb') as f:
            f.write(bytes(stored_variant_did_doc_bytes.encode('utf-8')))

    def save_keys(self, filename):
        """
        Persists a signing key doc to disk so it can be used to verify, sign and encrypt messages later. Throws on error.
        """
        # keyname = os.path.join(PEER_DID_STORAGE_FOLDER, get_did_from_doc(stored_variant_did_doc_bytes) + '.skey')
        keyname = os.path.join(PEER_DID_STORAGE_FOLDER, filename + '.keys')
        # Optional fanciness not shown here:
        #
        # 1. Tolerate the resolved variant of a DID doc. (Detect it by checking for the presence of
        #    a top-level "id" property, and subtract it to get the stored variant.)
        # 2. Specify a different folder where DID docs are stored.
        # 3. Input validation (make sure DID doc is valid).
        keys = {'secret_key':base64.b64encode(self.sk_hex.encode()),'verify_key':base64.b64encode(self.vk_hex.encode())}
        with open(keyname, 'wb') as f:
            f.write(pickle.dumps(keys))

    def resolve_did(self, did):
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

    def is_authorized(self, privilege, did_doc, *keys):
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

    def sign(self, content_bytes):
        return self.sk.sign(content_bytes)  # emit a JWS

    def verify(self, content_bytes, vkey, jws):
        return vkey.verify(jws, content_bytes)

    def connect(self, pthid, label, sig, diddoc, did):
        didcomm = {"@id": "5678876542345", "@type": "https://didcomm.org/didexchange/1.0/request",
                   "~thread": {"pthid": "<id of invitation>"}, "label": "<Bob>", "connection": {"did": "<B.did@B:A>",
                                                                                                "did_doc~attach": {
                                                                                                    "data": {
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

    def set_diddoc(self, endpoint):
        diddoc = {"@context": "https://w3id.org/did/v1", "publicKey": ["<pub key in base64"],
                  "service": [{"id": "default", "type": "didcomm", "serviceEndpoint": "<leogeo:A>"}]}

        # set public key value in hex format
        diddoc['publicKey'] = self.vk_hex
        # print(diddoc['publicKey'])
        # set service endpoint value
        diddoc['service'][0]['serviceEndpoint'] = endpoint
        # print(diddoc['service'][0]['serviceEndpoint'])
        return json.dumps(diddoc)

    def keys_to_hex(self, vk):
        # return hex version of key
        return ecdsa.VerifyingKey.to_string().hex(vk)

    def hex_to_keys(self, vk):
        # return normal version of key from hex
        return ecdsa.VerifyingKey.from_string(bytearray.fromhex(vk), curve=ecdsa.SECP256k1)

    def verify_didcomm(self, didcomm_message_b64):
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
        vk1 = self.hex_to_keys(vk)
        # extract signature
        sig = didcomm_message_json['connection']['did_doc~attach']['data']['sig']
        print(sig + '\n')
        # verify signature
        result = self.verify(diddoc, vk1, bytearray.fromhex(sig))
        print(
            '\nThe verification of the diddoc, verify key and signature extracted from didcomm_message match result: {}\n'.format(
                result))
        return diddoc, vk1, sig, result

    def icies_test(self, sk_hex, pk_hex, data):
        # assymtetric encryption/decryption test
        print(decrypt(sk_hex, encrypt(pk_hex, data)))
        secp_k = generate_key()
        sk_bytes = secp_k.secret  # bytes
        pk_bytes = secp_k.public_key.format(True)  # bytes
        print(decrypt(sk_bytes, encrypt(pk_bytes, data)))

    def encrypt_message(self, sk_hex, pk_hex, data):
        # encrypt message
        encrypted_data = encrypt(pk_hex, data)
        return encrypted_data

    def decrypt_message(self, sk_hex, pk_hex, data):
        # decrypt message
        decrypted_data = decrypt(sk_hex, data)
        return decrypted_data

    def send_message(self, pthid, label, sig, encrypted_message, did):
        # to implement
        didcomm = {"@id": "5678876542345", "@type": "https://didcomm.org/didexchange/1.0/request",
                   "~thread": {"pthid": "<id of invitation>"}, "label": "<Bob>", "connection": {"did": "<B.did@B:A>",
                                                                                                "message~attach": {
                                                                                                    "data": {
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

    def verify_message(self, didcomm_message_b64):
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
        diddoc = self.resolve_did(did)
        # print(diddoc)
        diddoc_json = json.loads(diddoc.decode())

        # extract public key from diddoc
        vk = diddoc_json['publicKey']
        # print(vk + '\n')
        vk1 = self.hex_to_keys(vk)

        # verify signature
        result = self.verify(didcomm, vk1, bytearray.fromhex(sig))
        print(
            'The verification of the didcomm message result: {}'.format(
                result))
        return didcomm, vk1, sig, result

