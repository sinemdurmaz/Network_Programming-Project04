# CEN437 – Network Programming Project 04

**Prepared by Sinem Durmaz**
**2021556028**

**Custom Transport & Secure Application Protocol over HTTPS**

This submission implements a secure, reliable messaging system with multiple transport modes. It features a custom transport protocol design, application-layer message handling, and HTTPS tunneling capabilities.

## Features
- **Custom Transport Protocol:** Implements reliability over UDP using Stop-and-Wait ARQ, sequence numbers, and CRC32 checksums.
- **Application Protocol:** JSON-based messaging with defined types (HELLO, MODE_SELECT, CHAT, CHAT_ACK).
- **Security:** End-to-End Encryption (E2EE) using symmetric encryption (AES/Fernet) with Pre-Shared Key (PSK).
- **HTTPS Tunneling (OBFS):** Carries transport packets inside HTTP POST/GET requests to bypass firewalls and obfuscate traffic.
- **Multi-Mode Support:**
  - `default`: UDP (Plaintext)
  - `secure`: UDP + Encryption
  - `obfs`: HTTPS Tunneling (Plaintext)
  - `secure_obfs`: HTTPS Tunneling + Encryption

---

## Execution Guide 

The project files are structured to run directly with Python 3. Ensure strictly that you run the commands from the root directory of the project.

### 1. Prerequisites
Install the required libraries:
```bash
pip install -r requirements.txt
```
(Requires: flask, cryptography)

### 2. Certificate Generation 
Required for HTTPS (OBFS) modes. This script generates cert.pem and key.pem in the certs/ folder.

```bash
python scripts/hizli_sertifika.py
```

### 3. Start UDP Server 
Starts the server in UDP listening mode.

```bash
python server_udp.py --port 9000 --psk demo-password
```

### 4. Start HTTPS Server 
Starts the server in HTTPS (Flask) mode for tunneling.

```bash
python server_https.py --port 9443 --cert certs/cert.pem --key certs/key.pem --psk demo-password
```

### 5. Start Client 
You can start the client in different modes. Open a new terminal for each client.

Example: Secure OBFS Mode (Recommended for testing):

```bash
python client.py --mode secure_obfs --username Ahmet --https-url [https://127.0.0.1:9443](https://127.0.0.1:9443) --psk demo-password
```

### Other Modes Examples:

### Secure UDP:

```bash
python client.py --mode secure --username Sinem --udp-host 127.0.0.1 --udp-port 9000 --psk demo-password
```

### Plain OBFS (If server is started without PSK):

```bash
python client.py --mode obfs --username User1 --https-url [https://127.0.0.1:9443](https://127.0.0.1:9443)
```

## Project Structure
- `transport.py`: Custom transport layer (Header, ARQ, Checksum).
- `app_protocol.py`: Application message encoding/decoding.
- `security.py`: Encryption/Decryption logic.
- `server_udp.py`: Main UDP server implementation with "Guestbook" logic.
- `server_https.py`: HTTPS server implementation with Message Queueing.
- `client.py`: CLI client application handling threading.
- `common.py`: Shared constants and utility functions.
- `carriers/`: Adapter classes for different network carriers (UDP/HTTPS).
- `scripts/`: Helper scripts (e.g., `hizli_sertifika.py` for generating certs).
- `certs/`: Directory where generated SSL certificates are stored.


## Notes:
**Polling:** In HTTPS modes, clients automatically poll the server (GET /api/poll) to receive messages since HTTP is stateless.

**Self-Signed Certs:** The client is configured to disable TLS verification (verify=False) for ease of testing with self-signed certificates.

**Reliability:** The transport layer handles packet loss and reordering transparently, even over the HTTPS tunnel.