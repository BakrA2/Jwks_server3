import unittest
import requests
import json
import jwt
import datetime
from http.server import HTTPServer
from threading import Thread
from jwks_server import MyServer, hostName, serverPort


class TestJWKSAuthServer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        
        #start the server in seperate thread
        cls.server = HTTPServer((hostName, serverPort), MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):

       # Shutdown the server
        cls.server.shutdown()
        cls.server_thread.join()

    def test_get_jwks(self):

       # test the JWKS retrieval
        response = requests.get(f'http://{hostName}:{serverPort}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("keys", data)
        self.assertEqual(data["keys"][0]["kid"], "goodKID")
        self.assertEqual(data["keys"][0]["alg"], "RS256")

        # test non jwks path and returns 404
        response = requests.get(f'http://{hostName}:{serverPort}/.well-known/KEYS.json')
        self.assertEqual(response.status_code, 404)

    def test_post_auth(self):

        #test the /auth endpoint for generating a JWT token.
        response = requests.post(f'http://{hostName}:{serverPort}/auth')
        self.assertEqual(response.status_code, 200)
        token = response.text
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")

    def test_post_auth_expired(self):

       #test the /auth endpoint with an expired token.
        response = requests.post(f'http://{hostName}:{serverPort}/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        token = response.text
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")
        self.assertLess(decoded["exp"], int(datetime.datetime.utcnow().timestamp()))

    def test_unsupported_methods(self):

       #test unsupported HTTP methods such as PUT, DELETE, etc.
        for method in ['put', 'patch', 'delete', 'head']:
            req_method = getattr(requests, method)
            response = req_method(f'http://{hostName}:{serverPort}/auth')
            self.assertEqual(response.status_code, 405)


if __name__ == '__main__':
    unittest.main()
