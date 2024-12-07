# Jwks_server3
JWKS server project 3
By: Bakr Alkhalidi 
bma0152

Project 3 screenshots are Test_client3 and Test_suite3

This project is a simple JWT (JSON Web Token) authentication server built using Python's built-in `http.server` and the `cryptography` library for RSA key management. The server provides an endpoint for generating JWTs, as well as a JSON Web Key Set (JWKS) endpoint to verify the tokens.
## Features
- **JWT Authentication**: Generate and validate RS256 signed JWT tokens
- **JWKS Endpoint**: Serve public RSA keys in JWKS format
- **Token Expiration Handling**: Option to generate expired JWTs for testing.
- **User Registration**: Secure user registration with Argon2 password hashing
- **Basic HTTP Server**: Handles HTTP requests, including `GET` and `POST` methods, with custom logic for authentication.
- **Rate Limiting**: Protect against abuse with IP-based rate limiting
- **Database Storage**: SQLite-based persistence for:
  - Private keys
  - User credentials
  - Authentication logs
- **Key Encryption**: AES encryption for stored private keys
- **SQL Injection Prevention**: Parameterized queries for database operations

  
## Prerequisites
- Python 3.6 or above
- The following Python libraries:
  - `cryptography` (for RSA key generation and serialization)
  - `jwt` (for JWT creation)

Install the required libraries by running:

```bash
pip install -r requirements.txt
Then after generate a key then export. ex:
export NOT_MY_KEY='A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5pa'
```

## Running the server

creat a virtual enviorment.

run the main server by compiling:
python jwks_server.py

run the gade bot:
/gradebot project3

run the test client: 
python test_jwks_server.py
