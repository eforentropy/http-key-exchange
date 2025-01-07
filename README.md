# HTTP Key Exchange

A secure key exchange implementation using RSA and AES over HTTP, written in Rust. This project demonstrates a practical implementation of hybrid cryptography, where RSA is used for secure key exchange and AES keys are used for subsequent communications.

## Features

- 🔒 RSA-2048 for secure key exchange
- 🔑 AES-256 key generation
- 🌐 Simple HTTP API endpoints
- ⚡ Async implementation using Tokio and Axum
- 🦀 Pure Rust implementation

## How It Works

1. The server generates an RSA key pair on startup
2. The client requests the server's public key
3. The client generates an AES key and IV
4. The client encrypts the AES key + IV using the server's public key
5. The encrypted key is sent to the server
6. The server decrypts and stores the AES key for future communications

## Project Structure

```
.
├── client/         # Client implementation
│   └── src/main.rs # Client code
└── server/         # Server implementation
    └── src/main.rs # Server code
```

## Prerequisites

- Rust 
- Cargo package manager

## Setup and Running

1. Clone the repository:
```bash
git clone https://github.com/yourusername/http-key-exchange.git
cd http-key-exchange
```

2. Start the server:
```bash
cd server
cargo run
```

3. In a new terminal, run the client:
```bash
cd client
cargo run
```

## Security Note

This is a demonstration project showing how to implement secure key exchange. For production use, additional security measures should be implemented, such as:
- TLS/SSL for HTTP communications
- Proper error handling
- Key rotation
- Authentication mechanisms

## License

MIT License 