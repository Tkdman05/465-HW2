import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake import perform_handshake
from secure_record import SecureChannel

def test_modified_ciphertext():
    """Test that modified ciphertext is detected"""
    print("Testing modified ciphertext detection...")
    
    # Setup
    result = perform_handshake()
    session_id = result['gateway']['session_id']
    keys = result['gateway']['keys']
    
    gateway_channel = SecureChannel(session_id, keys, "gateway")
    node_channel = SecureChannel(session_id, keys, "node")
    
    # Create and seal a message
    msg = b"Secret message"
    sealed = gateway_channel.seal(msg)
    
    # Modify a byte in the ciphertext (after header, before MAC)
    tampered = bytearray(sealed)
    tampered[20] ^= 0xFF  # Flip bits in ciphertext
    
    # Try to open - should fail
    try:
        node_channel.open_record(bytes(tampered))
        assert False, "Modified ciphertext was not detected!"
    except ValueError as e:
        assert "MAC verification failed" in str(e)
        print("✓ Modified ciphertext correctly rejected")

if __name__ == "__main__":
    test_modified_ciphertext()
    print("\nModified ciphertext test passed!")