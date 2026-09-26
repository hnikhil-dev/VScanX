"""
VScanX Web3 Smart Contract Weak Randomness Detector
Detects use of predictable environmental variables for randomness (OWASP SC07:2026).
"""

from typing import Any, Dict

from modules.base_module import BaseModule


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


class WeakRandomnessDetector(BaseModule):
    def __init__(self, **kwargs):
        super().__init__()
        self.name = "Smart Contract Weak Randomness Detector"
        self.description = (
            "Analyzes bytecode for use of predictable environmental variables for randomness (OWASP SC07:2026)"
        )
        self.version = "1.0.0"
        self.request_cost = 3
        self.supported_technologies = ["smart-contract", "ethereum"]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        self.clear_results()
        rpc_url = kwargs.get("rpc_url") or getattr(self, "rpc_url", None)
        contract_address = kwargs.get("contract") or getattr(self, "contract", None)

        if not rpc_url or not contract_address:
            self.add_result(
                severity="INFO",
                finding="Web3 Scan Parameters Missing",
                details="Missing '--rpc-url' or '--contract' flags required for randomness analysis.",
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
            bytecode_bytes = w3.eth.get_code(checksum_address)
            bytecode = bytecode_bytes.hex()
        except Exception as e:
            self.add_result(
                severity="HIGH",
                finding="Failed to retrieve contract bytecode",
                details=f"Error accessing contract address {contract_address}: {e}",
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        if not bytecode or bytecode in ["", "0x", "0x0", "00"]:
            self.add_result(
                severity="HIGH",
                finding="Target is not a Contract Account",
                details=f"Address {contract_address} has no associated bytecode (EOA account).",
                confidence="HIGH",
                verified=True,
            )
            return {"module": self.name, "target": target, "findings": self.get_results()}

        # Predictable environmental opcodes:
        # TIMESTAMP: 0x42
        # NUMBER (block): 0x43
        # DIFFICULTY / PREVRANDAO: 0x44
        # BLOCKHASH: 0x40
        opcodes = extract_evm_opcodes(bytecode)
        vulnerabilities = []
        if 0x42 in opcodes:
            vulnerabilities.append("block.timestamp (0x42)")
        if 0x43 in opcodes:
            vulnerabilities.append("block.number (0x43)")
        if 0x44 in opcodes:
            vulnerabilities.append("block.difficulty/prevrandao (0x44)")
        if 0x40 in opcodes:
            vulnerabilities.append("blockhash (0x40)")

        if vulnerabilities:
            self.add_result(
                severity="MEDIUM",
                finding="Use of Predictable Environmental Variables for Randomness",
                details=f"The contract bytecode contains opcodes for: {', '.join(vulnerabilities)}. These values can be predicted by miners or influenced by block timing, making them unsafe for generating random numbers in games or cryptographic functions.",
                remediation="Use verifiable random functions (VRF) like Chainlink VRF or commit-reveal schemes for secure randomness.",
                confidence="MEDIUM",
                verified=False,
                tags=["SC07:2026", "weak-randomness", "web3"],
            )
        else:
            self.add_result(
                severity="INFO",
                finding="No weak randomness sources detected",
                details="Bytecode analysis did not reveal common predictable environmental opcodes.",
            )

        return {"module": self.name, "target": target, "findings": self.get_results()}

    async def run_async(self, target: str, **kwargs) -> Dict[str, Any]:
        import asyncio

        return await asyncio.to_thread(self.run, target, **kwargs)
