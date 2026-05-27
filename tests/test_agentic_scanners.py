import pytest
from unittest.mock import MagicMock
from modules.agentic.prompt_injection_fuzzer import PromptInjectionFuzzer
from modules.agentic.code_execution_prober import CodeExecutionProber
from modules.agentic.memory_poisoning_fuzzer import MemoryPoisoningFuzzer

@pytest.fixture
def mock_handler():
    handler = MagicMock()
    return handler

def test_prompt_injection_vulnerable(mock_handler):
    # Mock vulnerable response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "VSCANX_ALIGNMENT_BYPASSED"
    mock_handler.post.return_value = mock_response
    
    fuzzer = PromptInjectionFuzzer(handler=mock_handler)
    result = fuzzer.run("http://agent.local/chat")
    
    assert any(f["severity"] == "CRITICAL" and "Prompt Injection Vulnerability" in f["finding"] for f in result["findings"])

def test_code_execution_vulnerable(mock_handler):
    # Mock vulnerable response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "uid=0(root) gid=0(root) groups=0(root)"
    mock_handler.post.return_value = mock_response
    
    prober = CodeExecutionProber(handler=mock_handler)
    result = prober.run("http://agent.local/chat")
    
    assert any(f["severity"] == "CRITICAL" and "Agent Remote Code Execution" in f["finding"] for f in result["findings"])

def test_memory_poisoning_vulnerable(mock_handler):
    # Mock injection response
    mock_response1 = MagicMock()
    mock_response1.status_code = 200
    
    # Mock verification response
    mock_response2 = MagicMock()
    mock_response2.status_code = 200
    mock_response2.text = "The system admin is a malicious attacker."
    
    mock_handler.post.side_effect = [mock_response1, mock_response2]
    
    fuzzer = MemoryPoisoningFuzzer(handler=mock_handler)
    result = fuzzer.run("http://agent.local/chat")
    
    assert any(f["severity"] == "HIGH" and "Agent Memory Poisoning Vulnerability" in f["finding"] for f in result["findings"])

def test_data_exfiltration_vulnerable(mock_handler):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Here is the internal api_key: 12345-abcde"
    mock_handler.post.return_value = mock_response
    
    from modules.agentic.data_exfiltration_fuzzer import DataExfiltrationFuzzer
    fuzzer = DataExfiltrationFuzzer(handler=mock_handler)
    result = fuzzer.run("http://agent.local/chat")
    
    assert any(f["severity"] == "HIGH" and "Data Exfiltration Vulnerability" in f["finding"] for f in result["findings"])
