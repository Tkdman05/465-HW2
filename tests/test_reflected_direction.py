import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake import perform_handshake
from secure_record import SecureChannel

def test_reflected_direction():
    """Test that record reflected into opposite direction is rejected"""
    print("Testing reflected direction detection...")
    
    # Setup
    result = perform_handshake()
    session_id = result['gateway']['session_id']  
    keys = result['gateway']['keys']
    
    gateway_channel = SecureChannel(session_id, keys, "gateway")
    
    # Gateway sends a message (direction = gateway-to-node)
    msg = b"Gateway message"
    sealed = gateway_channel.seal(msg)
    
    # Try to reflect it back to gateway (should fail on direction check)
    try:
        gateway_channel.open_record(sealed)
        assert False, "Reflected message was not detected!"
    except ValueError as e:
        assert "Wrong direction" in str(e)
        print("✓ Reflected record correctly rejected")

if __name__ == "__main__":
    test_reflected_direction()
    print("\nReflected direction test passed!")