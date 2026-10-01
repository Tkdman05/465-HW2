import os
import struct
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.backends import default_backend

class HandshakeParty:
    """Base class for handshake participants"""
    
    def __init__(self, identity, role, rsa_key=None):
        self.identity = identity.encode() if isinstance(identity, str) else identity
        self.role = role.encode() if isinstance(role, str) else role
        
        # Generate RSA key if not provided
        if rsa_key is None:
            self.rsa_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=3072,
                backend=default_backend()
            )
        else:
            self.rsa_key = rsa_key
        
        self.rsa_public_key = self.rsa_key.public_key()
        
        # Will be set during handshake
        self.dh_private_key = None
        self.dh_public_key = None
        self.nonce = None
        self.peer_dh_public = None
        self.peer_nonce = None
        self.session_keys = None
        self.session_id = None

    def load_dh_parameters(self, filepath="ffdhe3072.pem"):
        """Load DH parameters from PEM file"""
        with open(filepath, 'rb') as f:
            params = serialization.load_pem_parameters(f.read(), backend=default_backend())
        return params

    def generate_dh_keys(self, params):
        """Generate ephemeral DH key pair"""
        self.dh_private_key = params.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        
    def generate_nonce(self):
        """Generate fresh 16-byte nonce"""
        self.nonce = os.urandom(16)
        return self.nonce

    def encode_dh_public_value(self, dh_public_key):
        """Encode DH public value as 384-byte big-endian"""
        # Get the public numbers
        public_numbers = dh_public_key.public_numbers()
        y = public_numbers.y
        
        # Convert to 384-byte big-endian (3072 bits / 8)
        y_bytes = y.to_bytes(384, byteorder='big')
        return y_bytes

    def create_transcript(self, gateway_identity, node_identity, 
                         gateway_dh_public, node_dh_public,
                         gateway_nonce, node_nonce):
        """Create canonical transcript with length-prefixed encoding"""
        fields = [
            b"CSCE465-HS-v2",
            b"ffdhe3072",
            gateway_identity,
            node_identity,
            gateway_dh_public,
            node_dh_public,
            gateway_nonce,
            node_nonce
        ]
        
        transcript = b""
        for field in fields:
            # 4-byte big-endian length prefix
            transcript += struct.pack('>I', len(field))
            transcript += field
            
        return transcript

    def sign_transcript(self, transcript):
        """Sign role || SHA-256(transcript)"""
        # Hash the transcript
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(transcript)
        transcript_hash = digest.finalize()
        
        # Sign role || transcript_hash
        message = self.role + transcript_hash
        
        signature = self.rsa_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, signature, transcript, peer_role, peer_public_key):
        """Verify peer's signature"""
        # Hash the transcript
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(transcript)
        transcript_hash = digest.finalize()
        
        # Verify signature on role || transcript_hash
        message = peer_role + transcript_hash
        
        try:
            peer_public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def derive_keys(self, transcript):
        """Derive session keys using specified KDF"""
        # Compute shared secret Z
        shared_key = self.dh_private_key.exchange(self.peer_dh_public)
        # Encode as 384-byte big-endian
        Z = int.from_bytes(shared_key, byteorder='big').to_bytes(384, byteorder='big')
        
        # TH = SHA-256(transcript)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(transcript)
        TH = digest.finalize()
        
        # K_master = SHA-256("CSCE465-KDF-v1" || Z || TH)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(b"CSCE465-KDF-v1")
        digest.update(Z)
        digest.update(TH)
        K_master = digest.finalize()
        
        # Derive keys using HMAC
        def hmac_derive(key, label):
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(label + TH)
            return h.finalize()
        
        self.session_keys = {
            'K_g2n_enc': hmac_derive(K_master, b"gateway-to-node encryption"),
            'K_g2n_mac': hmac_derive(K_master, b"gateway-to-node MAC"),
            'K_n2g_enc': hmac_derive(K_master, b"node-to-gateway encryption"),
            'K_n2g_mac': hmac_derive(K_master, b"node-to-gateway MAC")
        }
        
        # Session ID = first 8 bytes
        session_id_full = hmac_derive(K_master, b"session identifier")
        self.session_id = session_id_full[:8]
        
        return self.session_keys, self.session_id


def perform_handshake(gateway_identity="gateway", node_identity="node"):
    """Perform complete handshake between gateway and node"""
    
    # Create parties
    gateway = HandshakeParty(gateway_identity, "gateway")
    node = HandshakeParty(node_identity, "node")
    
    # Load DH parameters
    dh_params = gateway.load_dh_parameters("ffdhe3072.pem")
    
    # Generate ephemeral DH keys
    gateway.generate_dh_keys(dh_params)
    node.generate_dh_keys(dh_params)
    
    # Generate nonces
    gateway_nonce = gateway.generate_nonce()
    node_nonce = node.generate_nonce()
    
    # Encode DH public values
    gateway_dh_public = gateway.encode_dh_public_value(gateway.dh_public_key)
    node_dh_public = node.encode_dh_public_value(node.dh_public_key)
    
    # Create transcript
    transcript = gateway.create_transcript(
        gateway.identity, node.identity,
        gateway_dh_public, node_dh_public,
        gateway_nonce, node_nonce
    )
    
    # Gateway signs
    gateway_signature = gateway.sign_transcript(transcript)
    
    # Node signs  
    node_signature = node.sign_transcript(transcript)
    
    # Exchange and verify signatures
    # Gateway verifies node's signature
    gateway.peer_dh_public = node.dh_public_key
    gateway.peer_nonce = node_nonce
    if not gateway.verify_signature(node_signature, transcript, b"node", node.rsa_public_key):
        raise ValueError("Gateway: Failed to verify node signature")
    
    # Node verifies gateway's signature
    node.peer_dh_public = gateway.dh_public_key
    node.peer_nonce = gateway_nonce
    if not node.verify_signature(gateway_signature, transcript, b"gateway", gateway.rsa_public_key):
        raise ValueError("Node: Failed to verify gateway signature")
    
    # Derive keys
    gateway_keys, gateway_session_id = gateway.derive_keys(transcript)
    node_keys, node_session_id = node.derive_keys(transcript)
    
    # Verify same session ID
    if gateway_session_id != node_session_id:
        raise ValueError("Session ID mismatch")
    
    return {
        'gateway': {
            'keys': gateway_keys,
            'session_id': gateway_session_id
        },
        'node': {
            'keys': node_keys,
            'session_id': node_session_id
        }
    }


if __name__ == "__main__":
    # Test the handshake
    try:
        result = perform_handshake()
        print("Handshake successful")
        print(f"Session ID: {result['gateway']['session_id'].hex()}")
        print(f"Gateway has keys: {list(result['gateway']['keys'].keys())}")
        print(f"Node has keys: {list(result['node']['keys'].keys())}")
        
        # Verify keys match appropriately
        assert result['gateway']['keys']['K_g2n_enc'] == result['node']['keys']['K_g2n_enc']
        assert result['gateway']['keys']['K_g2n_mac'] == result['node']['keys']['K_g2n_mac']
        assert result['gateway']['keys']['K_n2g_enc'] == result['node']['keys']['K_n2g_enc']
        assert result['gateway']['keys']['K_n2g_mac'] == result['node']['keys']['K_n2g_mac']
        print("Key derivation verified: Both parties derived identical keys")
        
    except Exception as e:
        print(f"Handshake failed: {e}")