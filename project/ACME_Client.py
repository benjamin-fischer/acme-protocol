import requests
import json
import base64
import time

from os.path import join, dirname, realpath
from multiprocessing import Process
from flask import Flask, Response, request, make_response
from DNS_Server import FixedResolver, DNS_Server
from datetime import datetime, timezone, timedelta

from hashlib import sha256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

DNS_SERVER_PORT = 10053
CHALLENGE_HTTP_SERVER_PORT = 5002
CERTIFICATE_HTTPS_SERVER_PORT = 5001
SHUTDOWN_HTTP_SERVER_PORT = 5003

ACME_SERVER_CA_PATH = join(dirname(realpath(__file__)), "pebble.minica.pem")

class ACME_Client:
    
    def __init__(self, dir_url, ipv4_address, domains):

        self.ACME_SERVER_DIR_URL = dir_url
        self.ipv4_address = ipv4_address
        self.domains = domains

        self.KEY_CHANGE_URL = ""
        self.NEW_ACCOUNT_URL = ""
        self.NEW_NONCE_URL = ""
        self.NEW_ORDER_URL = ""
        self.REVOKE_CERT_URL = ""

        self.nonce = None
        self.private_key = None
        self.public_key = None
        self.n = None
        self.e = None
        self.kid = None
        self.private_key_certificate = None
        self.private_key_pem = None

        self.order_url = ""
        self.authorizations_urls = []
        self.finalize_url = ""
        self.challenges = []
        self.key_authorizations = []
        self.tokens = []
        self.certificate_url = ""
        self.certificate_string = ""
        self.certificate_pem = None
        self.certificate_der = None

        self.dns_server = DNS_Server(zone=". 60 IN A " + self.ipv4_address, ipv4_address=self.ipv4_address, udp_port=DNS_SERVER_PORT)
        self.dns_server.start()
        self.certificate_https_server = None


    def url_safe_b64(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, int):
            data = data.to_bytes((data.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(data).decode("utf-8").replace('=', '')

    def get_directory(self):
        print("*** GET DIRECTORY ***")
        response = requests.get(url=self.ACME_SERVER_DIR_URL, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 200:
            content = json.loads(response.text)
            self.KEY_CHANGE_URL = content["keyChange"]
            self.NEW_ACCOUNT_URL = content["newAccount"]
            self.NEW_NONCE_URL = content["newNonce"]
            self.NEW_ORDER_URL = content["newOrder"]
            self.REVOKE_CERT_URL = content["revokeCert"]

    def get_nonce(self):
        print("*** GET NONCE ***")
        response = requests.head(url=self.NEW_NONCE_URL, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 200:
            self.nonce = response.headers["Replay-Nonce"]

    def key_generation(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.n = self.url_safe_b64(self.public_key.public_numbers().n)
        self.e = self.url_safe_b64(self.public_key.public_numbers().e)

    def jwk(self):
        return {"kty": "RSA", "n": self.n, "e": self.e}

    def create_protected_header(self, url):
        if url == self.NEW_ACCOUNT_URL:
            return self.url_safe_b64(json.dumps({"alg": "RS256", "jwk": self.jwk(), "nonce": self.nonce, "url": url}).encode("utf-8"))
        else:
            return self.url_safe_b64(json.dumps({"alg": "RS256", "kid": self.kid, "nonce": self.nonce, "url": url}).encode("utf-8"))

    def create_payload(self, payload):
        if payload == "":
            return payload
        else:
            return self.url_safe_b64(json.dumps(payload).encode("utf-8"))

    def create_signature(self, protected, payload):
        return self.url_safe_b64(self.private_key.sign("{}.{}".format(protected, payload).encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()))

    def create_signed_request(self, payload, url):
        headers = {"Content-type": "application/jose+json"}
        protected = self.create_protected_header(url)
        payload = self.create_payload(payload)
        signature = self.create_signature(protected, payload)
        body = json.dumps({"protected": protected, "payload": payload, "signature": signature})
        return headers, body

    def create_account(self):
        print("*** CREATE ACCOUNT ***")
        headers, body = self.create_signed_request({"termsOfServiceAgreed": True}, self.NEW_ACCOUNT_URL)
        response = requests.post(url=self.NEW_ACCOUNT_URL, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 201:
            self.nonce = response.headers["Replay-Nonce"]
            self.kid = response.headers["Location"]

    def submit_order(self):
        print("*** SUBMIT ORDER ***")
        identifiers = [{"type": "dns", "value": domain[0]} for domain in self.domains]
        headers, body = self.create_signed_request({"identifiers": identifiers}, self.NEW_ORDER_URL)
        response = requests.post(url=self.NEW_ORDER_URL, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 201:
            self.nonce = response.headers["Replay-Nonce"]
            self.order_url = response.headers["Location"]
            self.authorizations_urls = response.json()["authorizations"]
            self.finalize_url = response.json()["finalize"]

    def fetch_challenges(self):
        print("*** FETCH CHALLENGE ***")
        for i in range(len(self.domains)):
            headers, body = self.create_signed_request("", self.authorizations_urls[i])
            response = requests.post(url=self.authorizations_urls[i], data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
            print("Status Code : ", response.status_code)
            if response.status_code == 200:
                self.nonce = response.headers["Replay-Nonce"]
                self.challenges.append(response.json()["challenges"])

    def validate_http_challenges(self):
        print("*** VALIDATE HTTP CHALLENGES ***")
        challenge_urls = []
        self.key_authorizations = []
        for i in range(len(self.challenges)):
            for j in range(len(self.challenges[i])):
                if self.challenges[i][j]["type"] == "http-01":
                    url = self.challenges[i][j]["url"]
                    challenge_urls.append(url)
                    token = self.challenges[i][j]["token"]
                    self.tokens.append(token)
                    account_key = json.dumps(self.jwk(), sort_keys=True, separators=(',', ':'))
                    thumbprint = sha256(account_key.encode("utf-8")).digest()
                    self.key_authorizations.append(token + '.' + self.url_safe_b64(thumbprint))
        for i in range(len(self.domains)):
            app = Flask("CHALLENGE HTTP SERVER")
            @app.route('/.well-known/acme-challenge/<token>', methods=['GET', 'POST'])
            def respond_http_challenge(token):
                for i in range(len(self.tokens)):
                    if self.tokens[i] == token:
                        response = make_response(self.key_authorizations[i], 200)
                        response.headers["Content-Type"] = "application/octet-stream"
                        return response
            @app.route('/shutdown',  methods=["GET"])
            def shutdown():
                request.environ.get('werkzeug.server.shutdown')
                return None
            challenge_http_server = Process(target=app.run, kwargs={"host": self.ipv4_address, "port": CHALLENGE_HTTP_SERVER_PORT})
            challenge_http_server.start()
            time.sleep(2)
            headers, body = self.create_signed_request({}, challenge_urls[i])
            response = requests.post(url=challenge_urls[i], data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
            print("Status Code : ", response.status_code)
            print("Challenge Status : ", response.json()["status"])
            if response.status_code == 200:
                self.nonce = response.headers["Replay-Nonce"]
            while(True):
                print("*** POLL CHALLENGE STATUS ***")
                time.sleep(2)
                headers, body = self.create_signed_request("", self.authorizations_urls[i])
                response = requests.post(url=self.authorizations_urls[i], data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
                print("Status Code : ", response.status_code)
                print("Challenge Status : ", response.json()["status"])
                if response.status_code == 200:
                    self.nonce = response.headers["Replay-Nonce"]
                if response.json()["status"] == "valid":
                    break
            challenge_http_server.terminate()
            challenge_http_server.join()

    def validate_dns_challenges(self):
        print("*** VALIDATE DNS CHALLENGES ***")
        challenge_urls = []
        digests = []
        for i in range(len(self.challenges)):
            for j in range(len(self.challenges[i])):
                if self.challenges[i][j]["type"] == "dns-01":
                    url = self.challenges[i][j]["url"]
                    challenge_urls.append(url)
                    token = self.challenges[i][j]["token"]
                    account_key = json.dumps(self.jwk(), sort_keys=True, separators=(',', ':'))
                    thumbprint = sha256(account_key.encode("utf-8")).digest()
                    key_authorization = token + '.' + self.url_safe_b64(thumbprint)
                    digest = self.url_safe_b64(sha256(key_authorization.encode("utf-8")).digest())
                    digests.append(digest)
        for i in range(len(self.domains)):
            zone = "_acme-challenge." + self.domains[i][0] + ". 300 IN TXT " + digests[i]
            self.dns_server.start_challenge_mode(zone, challenge_urls[i])
            time.sleep(2)
            headers, body = self.create_signed_request({}, challenge_urls[i])
            response = requests.post(url=challenge_urls[i], data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
            print("Status Code : ", response.status_code)
            print("Challenge Status : ", response.json()["status"])
            if response.status_code == 200:
                self.nonce = response.headers["Replay-Nonce"]
            while(True):
                time.sleep(2)
                print("*** POLL CHALLENGE STATUS ***")
                headers, body = self.create_signed_request("", self.authorizations_urls[i])
                response = requests.post(url=self.authorizations_urls[i], data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
                print("Status Code : ", response.status_code)
                print("Challenge Status : ", response.json()["status"])
                if response.status_code == 200:
                    self.nonce = response.headers["Replay-Nonce"]
                if response.json()["status"] == "valid":
                    break
            self.dns_server.stop_challenge_mode()

    def poll_status(self):
        print("*** POLL ORDER STATUS ***")
        time.sleep(2)
        headers, body = self.create_signed_request("", self.order_url)
        response = requests.post(url=self.order_url, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        print("Order Status : ", response.json()["status"])
        if response.status_code == 200:
            self.nonce = response.headers["Replay-Nonce"]
        if response.json()["status"] == "valid":
            self.certificate_url = response.json()["certificate"]

    def finalize_order(self):
        print("*** FINALIZE ORDER ***")
        self.private_key_certificate = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.private_key_pem = self.private_key_certificate.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
        with open("private_key", 'wb+') as private_key_file:
            private_key_file.write(self.private_key_pem)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH")
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain[0]) for domain in self.domains]),
            critical=False,
        ).sign(self.private_key_certificate, hashes.SHA256(), default_backend())
        csr_der = csr.public_bytes(Encoding.DER)
        headers, body = self.create_signed_request({"csr": self.url_safe_b64(csr_der)}, self.finalize_url)
        response = requests.post(url=self.finalize_url, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        print("Order Status : ", response.json()["status"])
        if response.status_code == 200:
            self.nonce = response.headers["Replay-Nonce"]
      
    def download_certificate(self):
        print("*** DOWNLOAD CERTIFICATE ***")
        headers, body = self.create_signed_request("", self.certificate_url)
        response = requests.post(url=self.certificate_url, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 200:
            self.nonce = response.headers["Replay-Nonce"]
            self.certificate_string = response.content.decode("utf-8")
        self.certificate_pem = x509.load_pem_x509_certificate(self.certificate_string.encode("utf-8"), default_backend())
        self.certificate_der = self.certificate_pem.public_bytes(Encoding.DER)
        with open("certificate", 'wb+') as certificate_file:
            certificate_file.write(bytes(self.certificate_string, "ascii"))

    def return_certificate(self):
        app = Flask("CERTIFICATE HTTPS SERVER")
        @app.route("/",  methods=["GET"])
        def return_certificate():
            response = make_response(self.url_safe_b64(self.certificate_string), 200)
            response.headers["Content-Type"] = "application/octet-stream"
            return response
        @app.route('/shutdown',  methods=["GET"])
        def shutdown():
            request.environ.get('werkzeug.server.shutdown')
            return None
        self.certificate_https_server = Process(target=app.run,
            kwargs={
                "host": self.ipv4_address,
                "port": CERTIFICATE_HTTPS_SERVER_PORT ,
                "ssl_context": (join(dirname(realpath(__file__)), "certificate"), join(dirname(realpath(__file__)), "private_key"))
            }
        )
        self.certificate_https_server.start()
        time.sleep(2)

    def revoke_certificate(self):
        print("*** REVOKE CERTIFICATE ***")
        headers, body = self.create_signed_request({"certificate": self.url_safe_b64(self.certificate_der)}, self.REVOKE_CERT_URL)
        response = requests.post(url=self.REVOKE_CERT_URL, data=body, headers=headers, verify=ACME_SERVER_CA_PATH)
        print("Status Code : ", response.status_code)
        if response.status_code == 200:
            self.nonce = response.headers["Replay-Nonce"]
        time.sleep(2)
        self.certificate_https_server.terminate()
        self.certificate_https_server.join()

    def shutdown_servers(self):
        app = Flask("SHUTDOWN SERVER")
        @app.route('/shutdown',  methods=["GET"])
        def shutdown():
            print("SHUTTING DOWN DNS SERVER")
            self.dns_server.stop()
            print("SHUTTING DOWN CHALLENGE SERVER")
            requests.get(url="http://" + self.ipv4_address + ":" + CHALLENGE_HTTP_SERVER_PORT + "/shutdown")
            print("SHUTTING DOWN CERTIFICATE SERVER")
            requests.get(url="https://" + self.ipv4_address + ":" + CERTIFICATE_HTTPS_SERVER_PORT + "/shutdown")
            print("SHUTTING DOWN SHUTDOWN SERVER")
            request.environ.get('werkzeug.server.shutdown')
            
            return None
        app.run(host=self.ipv4_address, port=SHUTDOWN_HTTP_SERVER_PORT)  

