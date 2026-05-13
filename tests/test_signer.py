"""Ed25519签名验签单元测试。"""

import pytest

from src.crypto.key_manager import (
    generate_key_pair,
    get_public_key_fingerprint,
    save_private_key,
    load_private_key,
)
from src.crypto.signer import sign, verify


class TestKeyManager:
    def test_generate_key_pair(self):
        priv, pub = generate_key_pair()
        assert priv is not None
        assert pub is not None

    def test_key_pair_correspondence(self):
        priv, pub = generate_key_pair()
        data = b"test data"
        sig = sign(data, priv)
        assert verify(data, sig, pub)

    def test_fingerprint_format(self):
        _, pub = generate_key_pair()
        fp = get_public_key_fingerprint(pub)
        assert fp.startswith("SHA256:")
        assert len(fp) == 7 + 64  # "SHA256:" + 64 hex chars

    def test_save_and_load_key(self, tmp_path):
        priv, _ = generate_key_pair()
        key_path = str(tmp_path / "test_key.pem")
        save_private_key(priv, key_path)

        loaded = load_private_key(key_path)
        data = b"persistence test"
        sig = sign(data, loaded)
        pub = priv.public_key()
        assert verify(data, sig, pub)

    def test_different_keys_different_fingerprints(self):
        _, pub1 = generate_key_pair()
        _, pub2 = generate_key_pair()
        fp1 = get_public_key_fingerprint(pub1)
        fp2 = get_public_key_fingerprint(pub2)
        assert fp1 != fp2


class TestSigner:
    def test_sign_and_verify(self):
        priv, pub = generate_key_pair()
        data = b"hello, audit chain"
        signature = sign(data, priv)
        assert len(signature) == 64
        assert verify(data, signature, pub)

    def test_verify_wrong_data(self):
        priv, pub = generate_key_pair()
        data = b"original data"
        signature = sign(data, priv)
        assert not verify(b"tampered data", signature, pub)

    def test_verify_wrong_key(self):
        priv, _ = generate_key_pair()
        _, wrong_pub = generate_key_pair()
        data = b"test"
        signature = sign(data, priv)
        assert not verify(data, signature, wrong_pub)

    def test_empty_data(self):
        priv, pub = generate_key_pair()
        signature = sign(b"", priv)
        assert verify(b"", signature, pub)

    def test_large_data(self):
        priv, pub = generate_key_pair()
        data = b"x" * 100000
        signature = sign(data, priv)
        assert verify(data, signature, pub)
