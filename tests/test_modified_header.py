import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake import perform_handshake
from secure_record import SecureChannel

def test_modified_header():
    """Test that modified authenticated header is detected"""
    print("Testing modified header detection...")
    
    # Setup
    result = perform_handshake()
    session_id = result['gateway']['session_id']
    keys = result['gateway']['keys']
    
    gateway_channel = SecureChannel(session_id, keys, "gateway")
    node_channel = SecureChannel(session_id, keys, "node")
    
    # Create and seal a message
    msg = b"Test message"
    sealed = gateway_channel.seal(msg)
    
    # Modify the version byte in header (position 0)
    tampered = bytearray(sealed)
    tampered[0] = 0x99  # Change version byte
    
    # Try to open - should fail
    try:
        node_channel.open_record(bytes(tampered))
        assert False, "Modified header was not detected!"
    except ValueError:
        print("✓ Modified header correctly rejected")

if __name__ == "__main__":
    test_modified_header()
    print("\nModified header test passed!")