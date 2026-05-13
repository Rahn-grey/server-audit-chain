#!/usr/bin/env python3
"""生成Ed25519签名密钥对。

用法:
    python scripts/generate_keys.py [--output-dir ./keys]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.crypto.key_manager import (
    generate_key_pair,
    save_private_key,
    save_public_key,
    get_public_key_fingerprint,
)


def main():
    parser = argparse.ArgumentParser(description="生成Ed25519签名密钥对")
    parser.add_argument(
        "--output-dir", default="./keys",
        help="密钥输出目录（默认: ./keys）",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("正在生成Ed25519密钥对...")
    private_key, public_key = generate_key_pair()

    priv_path = str(output_dir / "audit_private.pem")
    pub_path = str(output_dir / "audit_public.pem")

    save_private_key(private_key, priv_path)
    save_public_key(public_key, pub_path)

    fp = get_public_key_fingerprint(public_key)
    print(f"私钥已保存: {priv_path}")
    print(f"公钥已保存: {pub_path}")
    print(f"公钥指纹: {fp}")


if __name__ == "__main__":
    main()
