import pytest
from unittest.mock import MagicMock, patch
from modules.web3.reentrancy_analyzer import ReentrancyAnalyzer
from modules.web3.access_control_checker import AccessControlChecker

@pytest.fixture
def mock_w3():
    with patch("modules.web3.reentrancy_analyzer.get_web3_client") as mock_get_re:
        with patch("modules.web3.access_control_checker.get_web3_client") as mock_get_ac:
            with patch("modules.web3.weak_randomness_detector.get_web3_client") as mock_get_wr:
                mock_w3_instance = MagicMock()
                mock_get_re.return_value = mock_w3_instance
                mock_get_ac.return_value = mock_w3_instance
                mock_get_wr.return_value = mock_w3_instance
                yield mock_w3_instance

def test_reentrancy_analyzer_no_call(mock_w3):
    mock_w3.is_connected.return_value = True
    mock_w3.to_checksum_address.return_value = "0x1234"
    mock_w3.eth.get_code.return_value = b"\x60\x80\x60\x40" 
    
    analyzer = ReentrancyAnalyzer()
    result = analyzer.run("0x1234", rpc_url="http://localhost:8545", contract="0x1234")
    assert any(f["severity"] == "INFO" and "No external CALL instructions" in f["details"] for f in result["findings"])

def test_reentrancy_analyzer_with_call(mock_w3):
    mock_w3.is_connected.return_value = True
    mock_w3.to_checksum_address.return_value = "0x1234"
    mock_w3.eth.get_code.return_value = b"\xf1" 
    
    analyzer = ReentrancyAnalyzer()
    result = analyzer.run("0x1234", rpc_url="http://localhost:8545", contract="0x1234")
    assert any(f["severity"] == "MEDIUM" and "Detected EVM CALL" in f["details"] for f in result["findings"])

def test_access_control_checker_vulnerable(mock_w3):
    mock_w3.is_connected.return_value = True
    mock_w3.to_checksum_address.return_value = "0x1234"
    mock_acct = MagicMock()
    mock_acct.address = "0x5678"
    mock_w3.eth.account.create.return_value = mock_acct
    mock_contract = MagicMock()
    mock_w3.eth.contract.return_value = mock_contract
    
    # Vulnerable: call() succeeds
    mock_func = MagicMock()
    mock_func.call.return_value = True
    mock_contract.functions.transferOwnership.return_value = mock_func
    
    checker = AccessControlChecker()
    result = checker.run("0x1234", rpc_url="http://localhost:8545", contract="0x1234")
    assert any(f["severity"] == "CRITICAL" and "Broken Access Control" in f["finding"] for f in result["findings"])

def test_access_control_checker_secure(mock_w3):
    mock_w3.is_connected.return_value = True
    mock_w3.to_checksum_address.return_value = "0x1234"
    mock_acct = MagicMock()
    mock_acct.address = "0x5678"
    mock_w3.eth.account.create.return_value = mock_acct
    mock_contract = MagicMock()
    mock_w3.eth.contract.return_value = mock_contract
    
    # Secure: all admin functions revert
    mock_reverting_func = MagicMock()
    mock_reverting_func.call.side_effect = Exception("revert")
    
    admin_funcs = ["transferOwnership", "setAdmin", "renounceOwnership", "pause", "unpause"]
    for name in admin_funcs:
        setattr(mock_contract.functions, name, MagicMock(return_value=mock_reverting_func))
    
    # owner/admin should succeed
    mock_owner_func = MagicMock()
    mock_owner_func.call.return_value = "0x9999"
    mock_contract.functions.owner.return_value = mock_owner_func
    mock_contract.functions.admin.return_value = mock_owner_func

    checker = AccessControlChecker()
    result = checker.run("0x1234", rpc_url="http://localhost:8545", contract="0x1234")
    assert any(f["severity"] == "INFO" and "Access Control Configuration Secure" in f["finding"] for f in result["findings"])

def test_weak_randomness_detector(mock_w3):
    mock_w3.is_connected.return_value = True
    mock_w3.to_checksum_address.return_value = "0x1234"
    # Bytecode with '42' (TIMESTAMP)
    mock_w3.eth.get_code.return_value = b"\x42"
    
    from modules.web3.weak_randomness_detector import WeakRandomnessDetector
    detector = WeakRandomnessDetector()
    result = detector.run("0x1234", rpc_url="http://localhost:8545", contract="0x1234")
    assert any(f["severity"] == "MEDIUM" and "block.timestamp" in f["details"] for f in result["findings"])
