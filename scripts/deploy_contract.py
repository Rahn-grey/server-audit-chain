#!/usr/bin/env python3
"""编译并部署 AuditLedger.sol 到 FISCO BCOS 3.x 网络。

用法:
    # 编译 + 部署 (需要 solc 编译器)
    pip install py-solc-x
    python scripts/deploy_contract.py --compile

    # 仅部署（已有编译产物）
    python scripts/deploy_contract.py --endpoint 127.0.0.1:20200

    # 指定输出
    python scripts/deploy_contract.py --compile --output .env

原理:
    1. py-solc-x 编译 AuditLedger.sol → bytecode + ABI
    2. BCOSClient 发送部署交易
    3. 返回合约地址 → 写入环境变量文件
"""

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def compile_contract(sol_path: Path) -> dict:
    """使用 py-solc-x 编译 Solidity 合约。

    Returns:
        {"abi": [...], "bytecode": "0x..."}
    """
    try:
        from solcx import compile_standard, install_solc, set_solc_version
    except ImportError:
        print("[错误] 需要安装 py-solc-x: pip install py-solc-x")
        sys.exit(1)

    # 安装 solc 编译器（首次运行）
    try:
        install_solc("0.8.20")
        set_solc_version("0.8.20")
    except Exception:
        print("[警告] solc 自动安装失败，尝试使用系统 solc...")

    source = sol_path.read_text(encoding="utf-8")

    compiled = compile_standard({
        "language": "Solidity",
        "sources": {sol_path.name: {"content": source}},
        "settings": {
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode.object"]}
            }
        },
    }, allow_paths=[str(sol_path.parent)])

    contract_data = compiled["contracts"][sol_path.name]["AuditLedger"]
    bytecode = "0x" + contract_data["evm"]["bytecode"]["object"]
    abi = contract_data["abi"]

    # 保存编译产物
    build_dir = sol_path.parent / "build"
    build_dir.mkdir(exist_ok=True)

    (build_dir / "AuditLedger.abi").write_text(
        json.dumps(abi, indent=2), encoding="utf-8"
    )
    (build_dir / "AuditLedger.bin").write_text(bytecode, encoding="utf-8")

    print(f"  编译成功 → {build_dir}")
    print(f"    ABI:  {len(abi)} 个条目")
    print(f"    Bytecode: {len(bytecode)} 字符")
    return {"abi": abi, "bytecode": bytecode}


def deploy(bytecode: str, abi: list, endpoint: str) -> str:
    """部署合约到 FISCO BCOS 网络。

    使用 BCOSClient 或直接 JSON-RPC。

    Returns:
        合约地址。
    """
    # 尝试使用 SDK
    try:
        from bcos3sdk.bcos3client import Bcos3Client, Bcos3Config
        config = Bcos3Config()
        host, _, port_str = endpoint.partition(":")
        port = int(port_str) if port_str else 20200
        config.set_connection_config(endpoint=host, port=port)
        client = Bcos3Client(config)

        result = client.deploy(
            group_id=1,
            contract_name="AuditLedger",
            bytecode=bytecode,
            abi_info=json.dumps(abi),
        )
        address = result.get("contractAddress", "")
        print(f"  部署成功 (SDK)")
        return address
    except ImportError:
        print("  [信息] Python SDK 未安装，输出部署信息供手动部署")
        print("  手动部署步骤:")
        print("    1. 将 bcos/contract/build/AuditLedger.* 复制到 FISCO BCOS 控制台")
        print("    2. 在控制台中执行: deploy AuditLedger")
        print("    3. 将返回的合约地址写入 .env 文件")
        return ""


def main():
    parser = argparse.ArgumentParser(
        description="部署 AuditLedger.sol 到 FISCO BCOS 网络"
    )
    parser.add_argument("--endpoint", default="127.0.0.1:20200",
                       help="BCOS 节点 RPC 地址")
    parser.add_argument("--compile", action="store_true",
                       help="编译 Solidity 合约")
    parser.add_argument("--output", default=None,
                       help="合约地址输出文件 (如 .env)")
    args = parser.parse_args()

    sol_path = PROJECT_ROOT / "bcos" / "contract" / "AuditLedger.sol"
    if not sol_path.exists():
        print(f"[错误] 合约文件不存在: {sol_path}")
        sys.exit(1)

    print("=" * 60)
    print("  部署 AuditLedger.sol → FISCO BCOS 3.x")
    print("=" * 60)
    print(f"  节点:   {args.endpoint}")
    print(f"  合约:   {sol_path}")
    print()

    # 编译
    bytecode = ""
    abi = []

    build_bin = sol_path.parent / "build" / "AuditLedger.bin"
    build_abi = sol_path.parent / "build" / "AuditLedger.abi"

    if args.compile or not build_bin.exists():
        print("[1/2] 编译合约 ...")
        result = compile_contract(sol_path)
        bytecode = result["bytecode"]
        abi = result["abi"]
    else:
        print("[1/2] 加载已有编译产物 ...")
        bytecode = build_bin.read_text().strip()
        abi = json.loads(build_abi.read_text())
        print(f"  已加载: bytecode={len(bytecode)}字符, abi={len(abi)}个条目")

    # 部署
    print(f"\n[2/2] 部署到 {args.endpoint} ...")
    contract_addr = deploy(bytecode, abi, args.endpoint)

    if contract_addr:
        print(f"\n{'=' * 60}")
        print(f"  ✅ 合约部署成功")
        print(f"  合约地址: {contract_addr}")
        print(f"{'=' * 60}")
        print()
        print("  请设置环境变量:")
        print(f"    export BCOS_CONTRACT_ADDR={contract_addr}")
        print(f"    export AUDIT_SYSTEM_MODE=production")

        if args.output:
            output_path = Path(args.output)
            with open(output_path, "a") as f:
                f.write(f"BCOS_CONTRACT_ADDR={contract_addr}\n")
            print(f"  已追加到: {args.output}")


if __name__ == "__main__":
    main()
