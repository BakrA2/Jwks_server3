# Jwks_server3
JWKS server project 3
By: Bakr Alkhalidi 
bma0152

Project 2 screenshots are Test_client2 and Test_suite2

This project is a simple JWT (JSON Web Token) authentication server built using Python's built-in `http.server` and the `cryptography` library for RSA key management. The server provides an endpoint for generating JWTs, as well as a JSON Web Key Set (JWKS) endpoint to verify the tokens.

## Features
- **JWT Issuing**: Generate signed JWT tokens for authentication with RSA-based signing (RS256).
- **JWKS Endpoint**: Serve the public RSA keys in JSON Web Key Set format for verifying issued tokens.
- **Token Expiration Handling**: Option to generate expired JWTs for testing.
- **Basic HTTP Server**: Handles HTTP requests, including `GET` and `POST` methods, with custom logic for authentication.
- **Database-poered persistence**: Uses SQLite to store private keys, ensuring their availability after server restarts or migrations.
- **SQL injection prevention**: Demonstrates safe database interactions by avoiding dynamic SQL queries and using query parameters.

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

run the main server by compiling:
python jwks_server.py    

run the gade bot:
/gradebot project3

run the test client: 
python test_jwks_server.py
