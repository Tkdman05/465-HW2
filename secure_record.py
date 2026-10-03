import struct
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class SecureChannel:
    """Secure bidirectional channel with encrypt-then-MAC protection"""
    
    VERSION = 0x01
    
    # Direction constants
    DIR_G2N = 0x01  # Gateway to Node
    DIR_N2G = 0x02  # Node to Gateway
    
    # Message types
    MSG_DATA = 0x01
    MSG_CONTROL = 0x02
    
    def __init__(self, session_id, keys, role="gateway"):
        """
        Initialize secure channel
        
        Args:
            session_id: 8-byte session identifier
            keys: Dictionary with K_g2n_enc, K_g2n_mac, K_n2g_enc, K_n2g_mac
            role: "gateway" or "node" to determine direction
        """
        self.session_id = session_id
        self.role = role
        
        # Set keys based on role
        if role == "gateway":
            self.send_enc_key = keys['K_g2n_enc']
            self.send_mac_key = keys['K_g2n_mac']
            self.recv_enc_key = keys['K_n2g_enc']
            self.recv_mac_key = keys['K_n2g_mac']
            self.send_direction = self.DIR_G2N
            self.recv_direction = self.DIR_N2G
        else:  # node
            self.send_enc_key = keys['K_n2g_enc']
            self.send_mac_key = keys['K_n2g_mac']
            self.recv_enc_key = keys['K_g2n_enc']
            self.recv_mac_key = keys['K_g2n_mac']
            self.send_direction = self.DIR_N2G
            self.recv_direction = self.DIR_G2N
        
        # Sequence numbers start at 0
        self.send_sequence = 0
        self.recv_sequence = 0
        
    def seal(self, plaintext, message_type=None):
        """
        Encrypt and authenticate a message
        
        Args:
            plaintext: bytes to encrypt
            message_type: optional message type (default: MSG_DATA)
            
        Returns:
            sealed record (header || ciphertext || tag)
        """
        if message_type is None:
            message_type = self.MSG_DATA
            
        # Get current sequence number
        sequence = self.send_sequence
        
        # Construct IV: session_id || sequence
        iv = self.session_id + struct.pack('>Q', sequence)
        
        # Encrypt with AES-256-CTR
        cipher = Cipher(
            algorithms.AES(self.send_enc_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Build header
        header = struct.pack(
            '>BBQBi',
            self.VERSION,           # version (1 byte)
            self.send_direction,    # direction (1 byte)
            sequence,               # sequence (8 bytes)
            message_type,           # message_type (1 byte)
            len(ciphertext)         # ciphertext_length (4 bytes)
        )
        
        # Compute MAC over header || iv || ciphertext
        h = hmac.HMAC(self.send_mac_key, hashes.SHA256(), backend=default_backend())
        h.update(header)
        h.update(iv)
        h.update(ciphertext)
        tag = h.finalize()
        
        # Increment sequence number
        self.send_sequence += 1
        
        # Return header || ciphertext || tag
        return header + ciphertext + tag
    
    def open_record(self, sealed_record):
        """
        Verify and decrypt a sealed record
        
        Args:
            sealed_record: bytes containing header || ciphertext || tag
            
        Returns:
            tuple (plaintext, message_type) on success
            
        Raises:
            ValueError: on any verification or format error
        """
        # Check minimum length (header=15 + tag=32 = 47 bytes minimum)
        if len(sealed_record) < 47:
            raise ValueError("Record too short")
        
        # Parse header
        header = sealed_record[:15]
        try:
            version, direction, sequence, message_type, ciphertext_length = struct.unpack(
                '>BBQBi', header
            )
        except struct.error:
            raise ValueError("Invalid header format")
        
        # Verify version
        if version != self.VERSION:
            raise ValueError(f"Invalid version: {version}")
        
        # Verify direction
        if direction != self.recv_direction:
            raise ValueError(f"Wrong direction: expected {self.recv_direction}, got {direction}")
        
        # Verify sequence number
        if sequence != self.recv_sequence:
            raise ValueError(f"Invalid sequence: expected {self.recv_sequence}, got {sequence}")
        
        # Check ciphertext length
        if ciphertext_length < 0:
            raise ValueError(f"Invalid ciphertext length: {ciphertext_length}")
        
        # Verify record length
        expected_length = 15 + ciphertext_length + 32  # header + ciphertext + tag
        if len(sealed_record) != expected_length:
            raise ValueError(f"Invalid record length: expected {expected_length}, got {len(sealed_record)}")
        
        # Extract ciphertext and tag
        ciphertext = sealed_record[15:15+ciphertext_length]
        tag = sealed_record[15+ciphertext_length:]
        
        # Reconstruct IV
        iv = self.session_id + struct.pack('>Q', sequence)
        
        # Verify MAC (constant-time through library)
        h = hmac.HMAC(self.recv_mac_key, hashes.SHA256(), backend=default_backend())
        h.update(header)
        h.update(iv)
        h.update(ciphertext)
        
        try:
            h.verify(tag)
        except InvalidSignature:
            raise ValueError("MAC verification failed")
        
        # Only decrypt after MAC verification succeeds
        cipher = Cipher(
            algorithms.AES(self.recv_enc_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Update sequence number only after successful verification
        self.recv_sequence += 1
        
        return plaintext, message_type


def seal(plaintext, session_id, keys, sequence_num=0, role="gateway", message_type=0x01):
    """
    Standalone seal function for single message encryption
    
    Args:
        plaintext: bytes to encrypt
        session_id: 8-byte session identifier
        keys: dictionary with encryption and MAC keys
        sequence_num: sequence number (default 0)
        role: "gateway" or "node"
        message_type: message type byte (default 0x01)
        
    Returns:
        sealed record
    """
    channel = SecureChannel(session_id, keys, role)
    channel.send_sequence = sequence_num
    return channel.seal(plaintext, message_type)


def open_record(sealed_record, session_id, keys, sequence_num=0, role="node"):
    """
    Standalone open_record function for single message decryption
    
    Args:
        sealed_record: encrypted and authenticated record
        session_id: 8-byte session identifier
        keys: dictionary with encryption and MAC keys
        sequence_num: expected sequence number (default 0)
        role: "gateway" or "node"
        
    Returns:
        tuple (plaintext, message_type)
        
    Raises:
        ValueError: on any verification error
    """
    channel = SecureChannel(session_id, keys, role)
    channel.recv_sequence = sequence_num
    return channel.open_record(sealed_record)


# Example usage and testing
if __name__ == "__main__":
    # Generate test keys and session ID
    test_keys = {
        'K_g2n_enc': os.urandom(32),
        'K_g2n_mac': os.urandom(32),
        'K_n2g_enc': os.urandom(32),
        'K_n2g_mac': os.urandom(32)
    }
    test_session_id = os.urandom(8)
    
    # Create channels for both parties
    gateway_channel = SecureChannel(test_session_id, test_keys, "gateway")
    node_channel = SecureChannel(test_session_id, test_keys, "node")
    
    # Test gateway to node communication
    print("Testing Gateway -> Node communication:")
    plaintext1 = b'{"action":"READ","path":"notes.txt"}'
    sealed1 = gateway_channel.seal(plaintext1)
    print(f"Sealed record length: {len(sealed1)} bytes")
    
    decrypted1, msg_type1 = node_channel.open_record(sealed1)
    assert decrypted1 == plaintext1
    print(f"✓ Message decrypted successfully: {decrypted1}")
    
    # Test node to gateway communication
    print("\nTesting Node -> Gateway communication:")
    plaintext2 = b'{"status":"success","content":"Hello World"}'
    sealed2 = node_channel.seal(plaintext2)
    
    decrypted2, msg_type2 = gateway_channel.open_record(sealed2)
    assert decrypted2 == plaintext2
    print(f"✓ Response decrypted successfully: {decrypted2}")
    
    # Test replay detection
    print("\nTesting replay protection:")
    try:
        # Try to replay the same message
        node_channel.open_record(sealed1)
        print("✗ Replay was not detected!")
    except ValueError as e:
        print(f"✓ Replay correctly rejected: {e}")
    
    # Test tampered ciphertext
    print("\nTesting tamper detection:")
    tampered = bytearray(sealed2)
    tampered[20] ^= 0xFF  # Flip bits in ciphertext
    try:
        gateway_channel.open_record(bytes(tampered))
        print("✗ Tampering was not detected!")
    except ValueError as e:
        print(f"✓ Tampering correctly rejected: {e}")
    
    print("\n✓ All basic tests passed!")