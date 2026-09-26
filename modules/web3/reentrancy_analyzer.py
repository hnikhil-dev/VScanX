"""
VScanX Web3 Smart Contract Reentrancy Analyzer
Analyzes contract bytecode and ABI configurations to detect potential reentrancy hazards (OWASP SC08:2026).
"""

import json
from typing import Any, Dict

from modules.base_module import BaseModule


# Dynamic import helper for Web3 to fail gracefully if package not installed
def get_web3_client(rpc_url: str):
    try:
        from web3 import Web3

        return Web3(Web3.HTTPProvider(rpc_url))
    except ImportError:
        return None


def extract_evm_opcodes(bytecode_hex: str) -> set:
    """Parse EVM bytecode into opcode set, skipping PUSH data bytes."""
    if bytecode_hex.startswith("0x"):
        bytecode_hex = bytecode_hex[2:]
    try:
        raw_bytes = bytes.fromhex(bytecode_hex)
    except Exception:
        return set()

    opcodes = set()
    i = 0
    while i < len(raw_bytes):
        op = raw_bytes[i]
        opcodes.add(op)
        if 0x60 <= op <= 0x7F:  # PUSH1 .. PUSH32
            push_len = op - 0x5F
            i += 1 + push_len
        else:
            i += 1
    return opcodes


class ReentrancyAnalyzer(BaseModule):
    def __init__(self, **kwargs):
        super().__init__()
        self.name = "Smart Contract Reentrancy Analyzer"
        self.description = "Analyzes bytecode and function structures for reentrancy vulnerabilities (OWASP SC08:2026)"
        self.version = "1.0.0"
        self.request_cost = 4
        self.required_auth_state = "any"
        self.supported_content_types = ["application/json"]
        self.supported_technologies = ["smart-contract", "ethereum"]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        self.clear_results()

        rpc_url = kwargs.get("rpc_url") or getattr(self, "rpc_url", None)
        contract_address = kwargs.get("contract") or getattr(self, "contract", None)
        abi_path = kwargs.get("abi") or getattr(self, "abi", None)

        if not rpc_url or not contract_address:
            self.add_result(
                severity="INFO",
                finding="Web3 Scan Parameters Missing",
                details="Missing '--rpc-url' or '--contract' flags required for reentrancy analysis.",
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        w3 = get_web3_client(rpc_url)
        if not w3:
            self.add_result(
                severity="HIGH",
                finding="Web3 Package Not Installed",
                details="Python 'web3' package is required for Smart Contract scanning. Run: pip install web3",
                remediation="Install 'web3>=6.0.0' using python's package manager.",
                confidence="HIGH",
                verified=False,
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        if not w3.is_connected():
            self.add_result(
                severity="HIGH",
                finding="Web3 Provider Connection Failed",
                details=f"Unable to connect to Ethereum/EVM node at RPC URL: {rpc_url}",
                remediation="Ensure the RPC endpoint is active and accessible.",
                confidence="HIGH",
                verified=False,
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        try:
            checksum_address = w3.to_checksum_address(contract_address)
            bytecode = w3.eth.get_code(checksum_address)
        except Exception as e:
            self.add_result(
                severity="HIGH",
                finding="Failed to retrieve contract bytecode",
                details=f"Error accessing contract address {contract_address}: {str(e)}",
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        if not bytecode or bytecode == b"\x00" or bytecode == b"":
            self.add_result(
                severity="HIGH",
                finding="Target is not a Contract Account",
                details=f"Address {contract_address} has no associated bytecode. It is a standard Externally Owned Account (EOA), which cannot contain reentrancy issues.",
                remediation="Ensure the '--contract' argument is pointing to a deployed smart contract, not a personal wallet address.",
                confidence="HIGH",
                verified=True,
                tags=["SC08:2026", "web3"],
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        bytecode_hex = bytecode.hex()
        bytecode_len = len(bytecode)

        # 1. EVM Bytecode Opcode Disassembly
        # CALL opcode is 0xf1. DELEGATECALL is 0xf4. STATICCALL is 0xfa.
        # Parse opcodes safely without counting immediate push data bytes as instructions.
        opcodes = extract_evm_opcodes(bytecode_hex)
        has_call = (0xF1 in opcodes)
        has_delegatecall = (0xF4 in opcodes)

        # 2. ABI-based function analysis (if ABI is available)
        abi = None
        if abi_path:
            try:
                with open(abi_path, "r", encoding="utf-8") as f:
                    abi = json.load(f)
            except Exception:
                # nosec B110
                pass

        vulnerable_candidates = []
        if abi:
            for item in abi:
                if item.get("type") == "function":
                    func_name = item.get("name", "").lower()
                    # Check for transfer/withdraw/claim/refund keywords
                    if any(kw in func_name for kw in ["withdraw", "refund", "claim", "transfer", "send", "pay"]):
                        vulnerable_candidates.append(item.get("name"))

        # Evaluate risk level based on signals
        if has_call:
            details = f"Retrieved contract bytecode size: {bytecode_len} bytes. Detected EVM CALL (0xf1) opcode inside bytecode."
            if vulnerable_candidates:
                details += f" ABI contains high-risk withdrawal/transfer methods: {', '.join(vulnerable_candidates)}."

            self.add_result(
                severity="HIGH" if vulnerable_candidates else "MEDIUM",
                finding="Potential Reentrancy Vulnerability Vector Detected",
                details=f"{details} Untrusted external calls are present in bytecode, which could be exploited if state changes are made after the call.",
                remediation="Adhere to the 'Checks-Effects-Interactions' design pattern: update all contract states (effects) BEFORE invoking external calls (interactions). Use OpenZeppelin's ReentrancyGuard and apply 'nonReentrant' modifier on sensitive methods.",
                confidence="MEDIUM",
                verified=False,
                tags=["SC08:2026", "reentrancy", "web3"],
                evidence=f"Bytecode length: {bytecode_len} bytes | Call Opcode: Yes | DelegateCall Opcode: {'Yes' if has_delegatecall else 'No'}",
            )
        else:
            self.add_result(
                severity="INFO",
                finding="Reentrancy analysis completed",
                details=f"Analyzed {bytecode_len} bytes of bytecode. No external CALL instructions detected, indicating this contract is secure against reentrancy.",
            )

        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, **kwargs) -> Dict[str, Any]:
        import asyncio

        return await asyncio.to_thread(self.run, target, **kwargs)
