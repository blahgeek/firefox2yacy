#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import typing as tp
import hashlib
import base64
import hmac
import math
import json
import six
import pickle
import random
import logging
import contextlib
from Crypto.Cipher import AES

from fxa.core import Session as FxASession
from fxa.crypto import quick_stretch_password
from syncclient.client import (SyncClient, FxAClient,
                               TOKENSERVER_URL, hexlify, sha256)


logger = logging.getLogger(__name__)


class KeyBundle:

    def __init__(self, encryption_key, hmac_key):
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key

    @classmethod
    def fromMasterKey(cls, master_key, info):
        key_material = HKDF(master_key, None, info, 2 * 32)
        return cls(key_material[:32], key_material[32:])


def HKDF_extract(salt, IKM, hashmod=hashlib.sha256):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = b"\x00" * hashmod().digest_size
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha256):
    """HKDF-Expand; see RFC-5869 for the details."""
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = b""
    output = []
    for i in range(1, N + 1):
        data = T + info + bytes(bytearray([i]))
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return b"".join(output)[:L]


def HKDF(secret, salt, info, size, hashmod=hashlib.sha256):
    """HKDF-extract-and-expand as a single function."""
    PRK = HKDF_extract(salt, secret, hashmod)
    return HKDF_expand(PRK, info, size, hashmod)


def decrypt_payload(payload: bytes, key_bundle: KeyBundle) -> dict:
    j = json.loads(payload)
    # Always check the hmac before decrypting anything.
    expected_hmac = hmac.new(key_bundle.hmac_key,
                             j['ciphertext'].encode(),
                             hashlib.sha256).hexdigest()
    if j['hmac'] != expected_hmac:
        raise ValueError("HMAC mismatch: %s != %s" %
                         (j['hmac'], expected_hmac))
    ciphertext = base64.b64decode(j['ciphertext'])
    iv = base64.b64decode(j['IV'])
    aes = AES.new(key_bundle.encryption_key, AES.MODE_CBC, iv)
    plaintext = aes.decrypt(ciphertext)
    plaintext = plaintext[:-plaintext[-1]]
    # Remove any CBC block padding, assuming it's a well-formed JSON payload.
    # plaintext = plaintext[:plaintext.rfind(b"}") + 1]
    return json.loads(plaintext)


def encrypt_payload(payload, key_bundle):
    payload = json.dumps(payload).encode()
    # pkcs#7 padding
    padding_size = (16 - (len(payload) % 16))
    payload += bytes(bytearray(padding_size for _ in range(padding_size)))

    iv = bytes(bytearray(random.randint(0, 255) for _ in range(16)))

    aes = AES.new(key_bundle.encryption_key, AES.MODE_CBC, iv)
    encrypted = aes.encrypt(payload)
    encrypted_b64 = base64.b64encode(encrypted)

    encrypted_hmac = hmac.new(
        key_bundle.hmac_key, encrypted_b64, hashlib.sha256).hexdigest()
    return {
        'hmac': encrypted_hmac,
        'IV': base64.b64encode(iv).decode(),
        'ciphertext': encrypted_b64.decode(),
    }


def _get_browserid_assertion(fxaSession, tokenserver_url=TOKENSERVER_URL):
    bid_assertion = fxaSession.get_identity_assertion(tokenserver_url)
    _, keyB = fxaSession.keys
    if isinstance(keyB, six.text_type):  # pragma: no cover
        keyB = keyB.encode('utf-8')
    return bid_assertion, hexlify(sha256(keyB).digest()[0:16])


def get_client_and_key(username: str, password: str, pickle_filename: tp.Optional[str]=None)\
    -> tuple[SyncClient, KeyBundle]:
    fxa_client = FxAClient()

    prev_session = None
    if pickle_filename:
        with contextlib.suppress(pickle.PickleError, FileNotFoundError):
            prev_session = pickle.load(open(pickle_filename, 'rb'))
            logger.info('Loaded previous session from pickle: ' + pickle_filename)

    if prev_session:
        session = FxASession(fxa_client, username,
                             quick_stretch_password(username, password),
                             prev_session.uid,
                             prev_session.token)
        session.keys = prev_session.keys
        session.check_session_status()
    else:
        session = fxa_client.login(username, password, keys=True)
        session.fetch_keys()

    if pickle_filename:
        logger.info('Dumping session info to pickle: ' + pickle_filename)
        pickle.dump(session, open(pickle_filename, 'wb'))

    bid_assertion_args = _get_browserid_assertion(session)
    client = SyncClient(*bid_assertion_args)

    # NOTE: fix "payload content and/or content_type cannot be empty without an explicit allowance"
    client.auth.always_hash_content = False
    sync_keys = KeyBundle.fromMasterKey(
        session.keys[1],
        b"identity.mozilla.com/picl/v1/oldsync")

    # Fetch the sync bundle keys out of storage.
    # They're encrypted with the account-level key.
    keys = decrypt_payload(client.get_record('crypto', 'keys')['payload'],
                           sync_keys)

    # There's some provision for using separate key bundles
    # for separate collections
    # but I haven't bothered digging through to see what that's about because
    # it doesn't seem to be in use, at least on my account.
    if keys["collections"]:
        raise RuntimeError("no support for per-collection key bundles")

    bulk_keys = KeyBundle(base64.b64decode(keys["default"][0]),
                          base64.b64decode(keys["default"][1]))
    return (client, bulk_keys)
