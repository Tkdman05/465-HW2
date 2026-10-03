## Prerequisites

- Python 3.8 or higher
- OpenSSL 3.0 or newer (for generating DH parameters)
- Ubuntu 24.04 or compatible environment

## Setup Instructions

1. **Create and activate Python virtual environment:**
```bash
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
```

2. **Install required packages:**
```bash
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

3. **Generate Diffie-Hellman parameters (required for Task 2):**
```bash
cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

4. **Verify DH parameters:**
```bash
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```
Should display: `DH Parameters: (3072 bit)` and `GROUP: ffdhe3072`

## Running the Tasks

### Task 1: Demonstrate CTR Mode Vulnerabilities
```bash
python baseline_ctr.py
```
Demonstrates why encryption alone is insufficient by showing bit-flipping and replay attacks on AES-CTR without MAC.

### Task 2: Authenticated Diffie-Hellman Handshake
```bash
python handshake.py
```
Performs authenticated key establishment between gateway and node using RSA signatures and ephemeral Diffie-Hellman.

### Task 3: Encrypt-then-MAC Record Layer
```bash
python secure_record.py
```
Tests the secure record layer implementation with AES-256-CTR encryption and HMAC-SHA-256 authentication.

### Task 4: Run Security Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Or run individual test files
python tests/test_valid_operations.py
python tests/test_modified_ciphertext.py
python tests/test_modified_header.py
python tests/test_replay_record.py
python tests/test_reflected_direction.py
python tests/test_handshake_attacks.py
```

## Implementation Details

- **Encryption**: AES-256 in CTR mode
- **Authentication**: HMAC-SHA-256
- **Key Exchange**: Finite-field Diffie-Hellman with ffdhe3072 group
- **Digital Signatures**: RSA-PSS with SHA-256 (3072-bit keys)
- **Key Derivation**: Custom KDF using SHA-256 and HMAC-SHA-256