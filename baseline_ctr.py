import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CTR:
    """Insecure CTR mode encryption without authentication"""
    
    def __init__(self):
        # Generate a random key
        self.key = os.urandom(32)  # AES-256
        self.processed_messages = []
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using AES-CTR"""
        # Generate random IV/nonce
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv, ciphertext
    
    def decrypt(self, iv, ciphertext):
        """Decrypt ciphertext using AES-CTR"""
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Process the message (simulating receiver processing)
        self.processed_messages.append(plaintext)
        print(f"Receiver processed: {plaintext.decode()}")
        
        return plaintext


def relay_function(iv, ciphertext, original_bytes, replacement_bytes, position):
    """
    Relay function that modifies ciphertext without knowing the key
    Exploits CTR mode's stream cipher property: C = P ⊕ K
    """
    # Calculate XOR mask to transform original to replacement
    xor_mask = bytes(o ^ r for o, r in zip(original_bytes, replacement_bytes))
    
    print(f"\nBit-flipping attack:")
    print(f"Original bytes: {original_bytes} (hex: {original_bytes.hex()})")
    print(f"Target bytes: {replacement_bytes} (hex: {replacement_bytes.hex()})")
    print(f"XOR mask: {xor_mask.hex()}")
    
    # Apply XOR mask to ciphertext at the correct position
    modified_ct = bytearray(ciphertext)
    for i, mask_byte in enumerate(xor_mask):
        modified_ct[position + i] ^= mask_byte
    
    return iv, bytes(modified_ct)


def main():
    # Initialize the CTR system
    system = CTR()
    
    # Original command
    original_command = b'{"action":"READ","path":"notes.txt"}'
    print(f"Original command: {original_command.decode()}")
    
    # Encrypt the command
    iv, ciphertext = system.encrypt(original_command)
    print(f"\nEncrypted (IV: {iv.hex()}, CT: {ciphertext.hex()})")
    
    # === ATTACK 1: Bit-flipping ===
    print("\n")
    print("ATTACK 1: BIT-FLIPPING")
    
    # Find position of "READ" in the plaintext
    read_position = original_command.find(b'READ')
    
    # "READ" to "EXEC"
    original_action = b'READ'
    modified_action = b'EXEC'
    
    # Perform bit-flipping attack
    modified_iv, modified_ct = relay_function(
        iv, ciphertext, 
        original_action, modified_action, 
        read_position
    )
    
    # Show XOR relationship
    print(f"\nXOR relationship demonstration:")
    for i, (o, m) in enumerate(zip(original_action, modified_action)):
        xor_val = o ^ m
        print(f"  Position {i}: '{chr(o)}' (0x{o:02x}) XOR 0x{xor_val:02x} = '{chr(m)}' (0x{m:02x})")
    
    # Decrypt modified ciphertext
    print(f"\nDecrypting modified ciphertext:")
    modified_plaintext = system.decrypt(modified_iv, modified_ct)
    print(f"Modified command received: {modified_plaintext.decode()}")
    
    # === ATTACK 2: Replay ===
    print("\n")
    print("ATTACK 2: REPLAY ATTACK")
    
    print("\nReplaying the same ciphertext...")
    
    # First replay
    print("\nReplay #1:")
    system.decrypt(iv, ciphertext)
    
    # Second replay
    print("\nReplay #2:")
    system.decrypt(iv, ciphertext)
    
    # Show that receiver processed the same message multiple times
    print(f"\n=== Summary ===")
    print(f"Total messages processed by receiver: {len(system.processed_messages)}")
    print("All processed messages:")
    for i, msg in enumerate(system.processed_messages, 1):
        print(f"  {i}. {msg.decode()}")

if __name__ == "__main__":
    main()