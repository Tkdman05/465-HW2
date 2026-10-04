import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake import perform_handshake
from secure_record import SecureChannel

def test_replay_record():
    """Test that replayed record is rejected"""
    print("Testing replay record detection...")
    
    # Setup
    result = perform_handshake()
    session_id = result['gateway']['session_id']
    keys = result['gateway']['keys']
    
    gateway_channel = SecureChannel(session_id, keys, "gateway")
    node_channel = SecureChannel(session_id, keys, "node")
    
    # Create and seal a message
    msg = b"Transfer $1000"
    sealed = gateway_channel.seal(msg)
    
    # First reception should succeed
    decrypted, _ = node_channel.open_record(sealed)
    assert decrypted == msg
    print("✓ First message received successfully")
    
    # Replay the same sealed record - should fail
    try:
        node_channel.open_record(sealed)
        assert False, "Replay was not detected!"
    except ValueError as e:
        assert "Invalid sequence" in str(e)
        print("✓ Replayed record correctly rejected")

if __name__ == "__main__":
    test_replay_record()
    print("\nReplay record test passed!")