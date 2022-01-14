import argparse
import time
import os

from os import path
from multiprocessing import Process
from flask import Flask, Response, request, make_response
from ACME_Client import ACME_Client
from DNS_Server import FixedResolver, DNS_Server


def main():

    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument("ctype", choices=["dns01", "http01"])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", required=True, nargs='+', action="append")
    parser.add_argument("--revoke", required=False, action="store_true")

    args = parser.parse_args()
    challenge_type = args.ctype
    dir_url = args.dir
    ipv4_address = args.record
    domains = args.domain
    revoke = args.revoke

    if os.path.exists("certificate"):
        os.remove("certificate")
    if os.path.exists("private_key"):
        os.remove("private_key")

    client = ACME_Client(dir_url, ipv4_address, domains)
    client.get_directory()
    client.get_nonce()
    client.key_generation()
    client.create_account()
    client.submit_order()
    client.fetch_challenges()

    if challenge_type == "http01":
        client.validate_http_challenges()
    elif challenge_type == "dns01":
        client.validate_dns_challenges()

    client.poll_status()
    client.finalize_order()
    client.poll_status()
    client.download_certificate()
    client.return_certificate()

    if revoke:
        client.revoke_certificate()

    client.shutdown_servers()

    
if __name__ == "__main__":
    main()
    