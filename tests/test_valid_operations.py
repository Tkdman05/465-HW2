import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake import perform_handshake
from secure_record import SecureChannel

def test_valid_handshake():
    """Test that a valid handshake succeeds"""
    print("Testing valid handshake...")
    
    # Perform handshake
    result = perform_handshake("gateway", "node")
    
    # Check that we got session IDs and keys
    assert result['gateway']['session_id'] is not None
    assert result['node']['session_id'] is not None
    assert result['gateway']['session_id'] == result['node']['session_id']
    
    # Check that keys exist
    assert 'K_g2n_enc' in result['gateway']['keys']
    assert 'K_g2n_mac' in result['gateway']['keys']
    assert 'K_n2g_enc' in result['gateway']['keys']
    assert 'K_n2g_mac' in result['gateway']['keys']
    
    print("✓ Valid handshake succeeded")
    return result

def test_bidirectional_messages():
    """Test bidirectional encrypted messages"""
    print("Testing bidirectional messages...")
    
    # Setup
    result = perform_handshake()
    session_id = result['gateway']['session_id']
    keys = result['gateway']['keys']
    
    gateway_channel = SecureChannel(session_id, keys, "gateway")
    node_channel = SecureChannel(session_id, keys, "node")
    
    # Gateway to Node
    msg1 = b"Hello from gateway"
    sealed1 = gateway_channel.seal(msg1)
    decrypted1, _ = node_channel.open_record(sealed1)
    assert decrypted1 == msg1
    print("✓ Gateway to Node message works")
    
    # Node to Gateway
    msg2 = b"Hello from node"
    sealed2 = node_channel.seal(msg2)
    decrypted2, _ = gateway_channel.open_record(sealed2)
    assert decrypted2 == msg2
    print("✓ Node to Gateway message works")

if __name__ == "__main__":
    test_valid_handshake()
    test_bidirectional_messages()
    print("\nAll valid operation tests passed!")