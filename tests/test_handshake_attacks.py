import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from handshake import HandshakeParty

def test_incorrect_rsa_key():
    """Test that incorrect RSA public key is rejected"""
    print("Testing incorrect RSA key detection...")
    
    # Create parties
    gateway = HandshakeParty("gateway", "gateway")
    node = HandshakeParty("node", "node")
    
    # Create an imposter with different RSA key
    imposter_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    
    # Setup handshake
    dh_params = gateway.load_dh_parameters("ffdhe3072.pem")
    gateway.generate_dh_keys(dh_params)
    node.generate_dh_keys(dh_params)
    
    gateway_nonce = gateway.generate_nonce()
    node_nonce = node.generate_nonce()
    
    # Create transcript
    gateway_dh_public = gateway.encode_dh_public_value(gateway.dh_public_key)
    node_dh_public = node.encode_dh_public_value(node.dh_public_key)
    
    transcript = gateway.create_transcript(
        gateway.identity, node.identity,
        gateway_dh_public, node_dh_public,
        gateway_nonce, node_nonce
    )
    
    # Node signs with imposter key instead of real key
    node.rsa_key = imposter_key
    bad_signature = node.sign_transcript(transcript)
    
    # Gateway verifies with real node's public key - should fail
    real_node = HandshakeParty("node", "node")
    gateway.peer_dh_public = node.dh_public_key
    gateway.peer_nonce = node_nonce
    
    verified = gateway.verify_signature(
        bad_signature, transcript, b"node", real_node.rsa_public_key
    )
    
    assert verified == False
    print("✓ Incorrect RSA key correctly rejected")

def test_invalid_signature():
    """Test that invalid RSA-PSS signature is rejected"""
    print("Testing invalid signature detection...")
    
    gateway = HandshakeParty("gateway", "gateway")
    node = HandshakeParty("node", "node")
    
    # Setup
    dh_params = gateway.load_dh_parameters("ffdhe3072.pem")
    gateway.generate_dh_keys(dh_params)
    node.generate_dh_keys(dh_params)
    
    gateway_nonce = gateway.generate_nonce()
    node_nonce = node.generate_nonce()
    
    gateway_dh_public = gateway.encode_dh_public_value(gateway.dh_public_key)
    node_dh_public = node.encode_dh_public_value(node.dh_public_key)
    
    transcript = gateway.create_transcript(
        gateway.identity, node.identity,
        gateway_dh_public, node_dh_public,
        gateway_nonce, node_nonce
    )
    
    # Create valid signature then corrupt it
    node_signature = node.sign_transcript(transcript)
    corrupted_signature = bytearray(node_signature)
    corrupted_signature[0] ^= 0xFF  # Corrupt the signature
    
    # Verification should fail
    gateway.peer_dh_public = node.dh_public_key
    gateway.peer_nonce = node_nonce
    
    verified = gateway.verify_signature(
        bytes(corrupted_signature), transcript, b"node", node.rsa_public_key
    )
    
    assert verified == False
    print("✓ Invalid signature correctly rejected")

def test_reflected_handshake():
    """Test that reflected handshake message is rejected"""
    print("Testing reflected handshake detection...")
    
    gateway = HandshakeParty("gateway", "gateway")
    
    # Setup with gateway talking to itself (reflection)
    dh_params = gateway.load_dh_parameters("ffdhe3072.pem")
    gateway.generate_dh_keys(dh_params)
    gateway_nonce = gateway.generate_nonce()
    gateway_dh_public = gateway.encode_dh_public_value(gateway.dh_public_key)
    
    # Create reflected transcript (gateway to gateway)
    transcript = gateway.create_transcript(
        gateway.identity, gateway.identity,
        gateway_dh_public, gateway_dh_public,
        gateway_nonce, gateway_nonce
    )
    
    # Gateway signs as "gateway" role
    gateway_signature = gateway.sign_transcript(transcript)
    
    # Try to verify as if from "node" role - should fail
    gateway.peer_dh_public = gateway.dh_public_key
    gateway.peer_nonce = gateway_nonce
    
    verified = gateway.verify_signature(
        gateway_signature, transcript, b"node", gateway.rsa_public_key
    )
    
    assert verified == False
    print("✓ Reflected handshake correctly rejected")

if __name__ == "__main__":
    test_incorrect_rsa_key()
    test_invalid_signature()
    test_reflected_handshake()
    print("\nAll handshake attack tests passed!")