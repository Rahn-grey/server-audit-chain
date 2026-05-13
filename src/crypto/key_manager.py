"""Ed25519密钥管理。"""

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)


def generate_key_pair():
    """生成Ed25519密钥对。

    Returns:
        (private_key, public_key): cryptography Ed25519密钥对象元组。
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, path: str):
    """私钥以PEM格式存储，文件权限600。"""
    pem_data = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(pem_data)
    path_obj.chmod(0o600)


def load_private_key(path: str):
    """从PEM文件加载私钥。"""
    from cryptography.hazmat.primitives import serialization

    pem_data = Path(path).read_bytes()
    return serialization.load_pem_private_key(pem_data, password=None)


def save_public_key(public_key, path: str):
    """存储公钥为PEM格式。"""
    pem_data = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).write_bytes(pem_data)


def load_public_key(path: str):
    """从PEM文件加载公钥。"""
    from cryptography.hazmat.primitives import serialization

    pem_data = Path(path).read_bytes()
    return serialization.load_pem_public_key(pem_data)


def get_public_key_fingerprint(public_key) -> str:
    """计算公钥SHA-256指纹，用于链上索引。

    Returns:
        形如 "SHA256:abc123..." 的指纹字符串。
    """
    raw_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return f"SHA256:{digest}"
