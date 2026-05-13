"""Ed25519签名与验签。"""

import logging

logger = logging.getLogger(__name__)


def sign(data: bytes, private_key) -> bytes:
    """Ed25519签名。

    Args:
        data: 待签名的数据字节串。
        private_key: Ed25519私钥对象。

    Returns:
        64字节签名值。
    """
    signature = private_key.sign(data)
    logger.debug("签名数据长度: %d 字节", len(data))
    logger.debug("签名值长度: %d 字节", len(signature))
    return signature


def verify(data: bytes, signature: bytes, public_key) -> bool:
    """Ed25519验签。

    Args:
        data: 原始数据字节串。
        signature: 64字节签名值。
        public_key: Ed25519公钥对象。

    Returns:
        True表示验证通过，False表示验证失败。
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False
