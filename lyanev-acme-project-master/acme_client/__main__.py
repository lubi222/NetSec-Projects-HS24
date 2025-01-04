from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from dnslib.server import DNSServer
from datetime import datetime

# RUN COMMANDS:

# python -m acme_client dns01 --dir https://localhost:14000/dir --record 10.233.70.111 --domain example.com --domain *.example.com 
# --record 10.233.70.120 --domain example.com --domain test.example.com
# check timings

# NOTE: HTTPS handler not reached in http01
# IDEA: abstract stuff in functions so you're sure both are using the same code
#
# maybe DNS doesnt redirect there

from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler
from acme_client.http_shutdown_handler import HTTPShutdownHandler
from acme_client.https_cert_handler import HTTPCertHandler

import argparse
import requests

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from flask import json
from ssl import SSLContext
import ssl
import os
import base64
import hashlib
from time import sleep



if __name__ == "__main__": #TODO: CLIENT SHOULD RUN UNTIL SHUTDOWN RECEIVED @ SHUTDOWN HTTP SERVER
    # Hint: You may want to start by parsing command line arguments and (should you make it not terminate?? i.e. wait for input as long as there is
    # maybe not cause they will just call run .. )
    # perform some sanity checks first. The built-in `argparse` library will suffice.

    acme_parser = argparse.ArgumentParser()
    acme_parser.add_argument('challenge_type', choices=['http01', 'dns01'])
    acme_parser.add_argument('--dir', required=True)
    acme_parser.add_argument('--record', required=True)
    acme_parser.add_argument('--domain', required=True, action='append' )
    acme_parser.add_argument('--revoke', action="store_true", required=False)
    final_args = acme_parser.parse_args() # dir is localhost:14000/dir
    # HTTP Servers
    http_shutdown_server = HTTPServer(("0.0.0.0", 5003), HTTPShutdownHandler)
    http01_server = HTTPServer(("0.0.0.0", 5002), HTTP01Handler)

    # DNS Server
    myDNS01Handler = DNS01Handler(defaultAResponse = final_args.record)
    dns01_server = DNSServer(myDNS01Handler, port=10053, address="0.0.0.0")

    http01_thread = Thread(target = http01_server.serve_forever)
    dns01_thread = Thread(target = dns01_server.server.serve_forever)
    http01_thread.daemon = False # TODO: TRY CHANGING
    # dns01_thread.daemon = True

    http_shutdown_thread = Thread(target = http_shutdown_server.serve_forever)
    # http_shutdown_thread.daemon = True # thinking: would otherwise exit if left


    http01_thread.start()
    dns01_thread.start()
    http_shutdown_thread.start()


    # TODO: http_shutdown_thread.start() 
    

    path_to_ca = os.path.join(os.getcwd(), 'project/pebble.minica.pem')
    
    req_dir_path = f'{final_args.dir}'
    res_dir = requests.get(req_dir_path, verify=path_to_ca)
    dir = res_dir.json()

    req_nonce_path = dir["newNonce"]
    res_nonce = requests.head(req_nonce_path, verify=path_to_ca)
    replay_nonce = res_nonce.headers["Replay-Nonce"]

    # create private-public keypair to use for POST and other requests with non-empty body
    full_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    
    public_key = full_key.public_key()
    public_key_numbers = public_key.public_numbers()

    req_account_path = dir["newAccount"]
    
    # DEFINE USEFUL FUNCTIONS FOR THE METHODS
    def base64url(data):

        if isinstance(data, dict):
            data = json.dumps(data).encode('utf-8')  # Convert to JSON string and encode as bytes
        
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8') # perform this as per standard, in byte mode


    def send_challenge_validate(replay_nonce, challenge_url):
            protected_cl_res = {
                "alg": "RS256",
                "kid": account_url, 
                "nonce": replay_nonce,
                "url": challenge_url
            }
            protected_cl_res_encoded = base64url(protected_cl_res)

            signing_input_cl_res = f"{protected_cl_res_encoded}.{base64url({})}".encode()
            signature_cl_res = full_key.sign(signing_input_cl_res, padding.PKCS1v15(), hashes.SHA256())
            signature_cl_res_encoded = base64url(signature_cl_res)

            cl_res_body = {
                "protected": protected_cl_res_encoded,
                "payload": base64url({}),
                "signature": signature_cl_res_encoded
            }

            
            # READY TO VALIDATE CHALLENGE REQUEST - POST authorization challenge urls
            challenge_validate_req = requests.post(challenge_url, data=json.dumps(cl_res_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
            return challenge_validate_req


    def poll_order(replay_nonce, order_url):
        protected_poll = {
            "alg": "RS256",
            "kid": account_url, 
            "nonce": replay_nonce,
            # "url": dns_challenge["url"]
            "url": order_url
        }
        protected_poll_encoded = base64url(protected_poll)

        sign_input_poll = f"{protected_poll_encoded}.".encode()
        sign_poll = full_key.sign(sign_input_poll, padding.PKCS1v15(), hashes.SHA256())
        sign_poll_encoded = base64url(sign_poll)

        poll_body = {
            "protected": protected_poll_encoded,
            "payload": "",
            "signature": sign_poll_encoded
        }
        # POLL FOR STATUS REQUEST -- #TODO: check if you have to change this URL to the order_url, although it seems to work now
        poll_for_status_res = requests.post(order_url, data=json.dumps(poll_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        return poll_for_status_res
        

    def send_CSR(replay_nonce, finalize_url, identifiers, domain_key):
        prot_csr = {
            "alg": "RS256",
            "kid": account_url,
            # "nonce": poll_for_status_res.headers["Replay-Nonce"],
            "nonce": replay_nonce,
            "url": finalize_url
        }
        
        prot_csr_encoded = base64url(prot_csr)
        # print("DOMAINS::: ", [domain for domain in challenges])
        my_subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain) for domain in identifiers])
        my_subject_name_alt = x509.SubjectAlternativeName([x509.DNSName(domain) for domain in identifiers])

        csr = x509.CertificateSigningRequestBuilder().subject_name(my_subject_name)\
            .add_extension(my_subject_name_alt, critical=False)\
            .sign(domain_key, hashes.SHA256())
            
        

        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_der_encoded = base64url(csr_der) #

        payload_csr = {
            "csr": csr_der_encoded
        }
        payload_csr_encoded = base64url(payload_csr)

        sign_input_csr = f"{prot_csr_encoded}.{payload_csr_encoded}".encode('utf-8')
        sign_csr = full_key.sign(sign_input_csr, padding.PKCS1v15(), hashes.SHA256()) # change this as well??? no cause same as other signs
        sign_csr_encoded = base64url(sign_csr)
        
        csr_msg = {
            "protected": prot_csr_encoded,
            "payload": payload_csr_encoded,
            "signature": sign_csr_encoded
        }
        # sleep(10)
        csr_res = requests.post(url=finalize_url, data=json.dumps(csr_msg), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        return csr_res
        
    def poll_certificate_status(replay_nonce, order_url):
        cert_poll_prot = {
            "alg": "RS256",
            "kid": account_url, 
            "nonce": replay_nonce,
            # "url": finalize_url
            "url": order_url # order url from Location field
        }
        cert_poll_prot_encoded = base64url(cert_poll_prot)

        sign_input_cert_poll = f"{cert_poll_prot_encoded}.".encode()
        sign_cert_poll = full_key.sign(sign_input_cert_poll, padding.PKCS1v15(), hashes.SHA256())
        sign_cert_poll_encoded = base64url(sign_cert_poll)


        cert_poll_body = {
            "protected": cert_poll_prot_encoded,
            "payload": "",
            "signature": sign_cert_poll_encoded
        }
        # POLL FOR CERT STATUS REQUEST -- POST-as-GET order


        poll_for_cert_status_res = requests.post(order_url, data=json.dumps(cert_poll_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        
        return poll_for_cert_status_res

    def download_certificate(replay_nonce, certificate_url):
        cert_dwnld_prot = {
            "alg": "RS256",
            "kid": account_url, 
            "nonce": replay_nonce,
            # "url": finalize_url
            "url": certificate_url # order url from Location field
        }
        cert_dwnld_prot_encoded = base64url(cert_dwnld_prot)

        sign_input_cert_dwnld = f"{cert_dwnld_prot_encoded}.".encode()
        sign_cert_dwnld = full_key.sign(sign_input_cert_dwnld, padding.PKCS1v15(), hashes.SHA256())
        sign_cert_dwnld_encoded = base64url(sign_cert_dwnld)


        cert_dwnld_body = {
            "protected": cert_dwnld_prot_encoded,
            "payload": "",
            "signature": sign_cert_dwnld_encoded
        }
        cert_dwnld_res = requests.post(certificate_url, data=json.dumps(cert_dwnld_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        # update nonce
        
        return cert_dwnld_res
    
    def save_certificate(domain_key, cert_path, domain_key_path):
        with open(cert_path, "wb") as my_certificate_file:
            my_certificate_file.write(cert_content)
        # print("saved cert to file!")

        # save domain key in file
        domain_key_to_save = domain_key.private_bytes(encoding=serialization.Encoding.PEM,\
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,\
                                                    encryption_algorithm=serialization.NoEncryption())

        with open(domain_key_path, "wb") as keyfile:
            keyfile.write(domain_key_to_save)

    def start_certificate_server(certfile, keyfile, path_to_ca):
        print('starting server')
        my_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        my_context.load_cert_chain(certfile=certfile, keyfile=keyfile)


        my_server = HTTPServer(('0.0.0.0', 5001), HTTPCertHandler)
        my_server.socket = my_context.wrap_socket(
            my_server.socket,
            server_side=True,
            
        )

        my_server_thread = Thread(target = my_server.serve_forever,)
        my_server_thread.daemon = True # not sure whether to leave this True or not
        # print('Starting certificate HTTPS Server... ')
        my_server_thread.start()
        
        return my_server

    def revoke_certificate(replay_nonce, certificate):
        revoke_prot = {
            "alg": "RS256",
            "kid": account_url,
            "nonce": replay_nonce,
            "url": dir["revokeCert"]
        }
        

        cert = x509.load_pem_x509_certificate(certificate)
        cert_der = cert.public_bytes(encoding = serialization.Encoding.DER)

    
        revoke_payload = {
            "certificate": base64url(cert_der) # assuming already in DER
        }

        signing_input_revoke = f"{base64url(revoke_prot)}.{base64url(revoke_payload)}".encode()
        signature_revoke = full_key.sign(signing_input_revoke, padding.PKCS1v15(), hashes.SHA256())
        

        revoke_body = {
            "protected": base64url(revoke_prot),
            "payload": base64url(revoke_payload),
            "signature": base64url(signature_revoke)
        }

        revoke_res = requests.post(dir["revokeCert"], data=json.dumps(revoke_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        # print("REVOKE RES::: ", revoke_res)

        curr_nonce = revoke_res.headers["Replay-Nonce"]
        return curr_nonce
    # find how to get what's inside jwk from RFC

    jwk = { # order matters apparently (because you hash it!)
        "kty": "RSA",
        "n": base64url(public_key_numbers.n.to_bytes(256, 'big')),
        "e": base64url(public_key_numbers.e.to_bytes(3, 'big'))
    }
    protected_body = {
        "alg": "RS256",
        "nonce": replay_nonce,
        "url": req_account_path,
        "jwk": jwk
    }
    payload_body = {
        "termsOfServiceAgreed": True
    }
    protected_body_encoded = base64url(protected_body)
    payload_body_encoded = base64url(payload_body)

    # maybe reformat this normally too

    signing_input = f"{protected_body_encoded}.{payload_body_encoded}".encode()
    signature = full_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_encoded = base64url(signature)

    post_request_body = {
        "protected": protected_body_encoded,
        "payload": payload_body_encoded,
        "signature": signature_encoded                           
    }
    jws_data = json.dumps(post_request_body)
    res_acc = requests.post(req_account_path, verify=path_to_ca, data=jws_data, headers={'Content-Type': 'application/jose+json'})
    
    req_neworder_path = dir["newOrder"]

    # get fresh nonce (!TODO or maybe source it from some header reply)
    res_nonce_fresh = requests.head(req_nonce_path, verify=path_to_ca)
    replay_nonce_fresh = res_nonce_fresh.headers["Replay-Nonce"]

    account_url = res_acc.headers["Location"] # print("ACCOUNT URL:::: ", account_url)

    protected = {
        "alg": "RS256",
        "kid": account_url,
        "nonce": replay_nonce_fresh,
        "url": req_neworder_path,
    }
    protected_encoded = base64url(protected)

    
    # identifiers = [ {"type": final_args.challenge_type[:-2], "value": id}  for id in final_args.domain]
    identifiers = [ {"type": "dns", "value": id}  for id in final_args.domain]
    # SHOULD BE ALL
    payload = {
        "identifiers": identifiers
    }
    # print("ORDER IDENTIFIERS ::::::::::::::::::::::::, ", identifiers)
    payload_encoded = base64url(payload)

    signing_input_order = f"{protected_encoded}.{payload_encoded}".encode()
    signature_order = full_key.sign(signing_input_order, padding.PKCS1v15(), hashes.SHA256())
    signature_order_encoded = base64url(signature_order)

    order_request_body = {
        "protected": protected_encoded,
        "payload": payload_encoded,
        "signature": signature_order_encoded
    }

    res_order = requests.post(req_neworder_path, data=json.dumps(order_request_body), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
    # print("RES ORDER::: ", res_order.json())
    finalize_url = res_order.json()["finalize"]
    authorizations = res_order.json()["authorizations"]

    # print("AUTHORIZATIONS (from res_order)::: ", authorizations)
    
    
    order_url = res_order.headers["Location"]


    auth_responses = []
    curr_nonce = res_order.headers["Replay-Nonce"]
    for authorization_url in authorizations:

        protected_auth = {
            "alg": "RS256",
            "kid": account_url,
            "nonce": curr_nonce,
            "url": authorization_url, 
        }
        protected_auth_encoded = base64url(protected_auth)

        sign_input_auth = f"{protected_auth_encoded}.".encode()
        sign_auth = full_key.sign(sign_input_auth, padding.PKCS1v15(), hashes.SHA256())
        sign_auth_encoded = base64url(sign_auth)

        auth_req_data = {
            "protected": protected_auth_encoded,
            "payload": "",
            "signature": sign_auth_encoded
        }

        auth_res = requests.post(authorization_url, data=json.dumps(auth_req_data), verify=path_to_ca, headers={'Content-Type': 'application/jose+json'})
        auth_responses.append(auth_res)

        # update nonce
        curr_nonce = auth_res.headers["Replay-Nonce"]
        

    # FULFILL REQUIREMENTS - CHALLENGES
        
    if(final_args.challenge_type == 'dns01'):
        # print("-IS HTTP SHUTDOWN ALIVE??? (start of dns)", http_shutdown_thread.is_alive())

        challenges = {} # we want challenge[domain] = list of challenges for this domain

        for auth_res in auth_responses:
            curr_identifier = auth_res.json()["identifier"]["value"]

            if "wildcard" in auth_res.json() and auth_res.json()["wildcard"] == True:
                curr_identifier = "WILDCARD_" + curr_identifier
                    
            curr_challenges = auth_res.json()["challenges"]
            dns_challenge = next((chall for chall in curr_challenges if chall["type"] == "dns-01"), None)
            challenges[curr_identifier] = dns_challenge

        # print("Challenges (DNS) from all responses::: ", challenges) 

        # JWK THUMBPRINT (RFC)
        jwk_dump = json.dumps({
            "e": jwk["e"],
            "kty": jwk["kty"],
            "n": jwk["n"],
        }, separators=(',', ':')).encode('utf-8')

        jwk_dump_hash = hashlib.sha256(jwk_dump).digest()
        jwk_thumbprint = base64url(jwk_dump_hash)

        # FULFILL REQUIREMENTS for each domain
        for domain in challenges:
            
            # myDNS01Handler.put_dnsRecord(domain, "0.0.0.0")

            token = challenges[domain]["token"] # (there really is only one challenge object behind each domain key)
            challenge_url = challenges[domain]["url"]
            
            key_authorization = f"{token}.{jwk_thumbprint}"
            key_authorization_digest = hashlib.sha256(key_authorization.encode('utf-8')).digest()
            key_authorization_digest_b64url = base64url(key_authorization_digest)

            # validation_domain_name = "_acme-challenge." + final_args.domain[0] + "."
            validation_domain_name = "_acme-challenge." + domain + "."
            
            # provision DNS record with digest value under that name (maybe change the 300 IN TXT later)
            myDNS01Handler.put_dnsRecord(validation_domain_name, key_authorization_digest_b64url)

            # READY TO VALIDATE CHALLENGES
            challenge_validate_req = send_challenge_validate(curr_nonce, challenge_url)
            curr_nonce = challenge_validate_req.headers["Replay-Nonce"] 

        # TODO::
        # retry_after_time = challenge_validate_req.headers["Retry-After"]

        sleep(4) 
        # # wait 2 sec then poll for challenge status #TODO SEE RETRY AFTER TIME - CURRENT TIME (code above)


        # POLL ORDER after challenges
        for domain in challenges.keys(): # TODO: maybe change this to poll actual challenges?? or to not loop over domains #maybe change this to just challenges
            poll_for_status_res = poll_order(replay_nonce=curr_nonce, order_url=order_url)


        curr_nonce = poll_for_status_res.headers["Replay-Nonce"]

        ## GENERATE DOMAIN KEY
        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


        dns_identifiers = [domain.replace('WILDCARD_', '*.') for domain in challenges]
        csr_res = send_CSR(replay_nonce=curr_nonce, finalize_url=finalize_url, identifiers=dns_identifiers, domain_key=domain_key)

        # check if retry after exists
        if "Retry-After" in csr_res.headers:

            retry_after_time = csr_res.headers["Retry-After"]
            if retry_after_time.isdigit():
                print(" DIGIIIIIIIIIIIIIIT :::!!!!!!!! INT INT INT INT ITN INT  ")
                sleep(int(retry_after_time) + 0.5)

            else :
                print("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATE ")
                date_format = '%a, %d %b %Y %H:%M:%S %Z'
                req_time = csr_res.headers["Date"]
                retry_after_time = datetime.strptime(retry_after_time, date_format)
                req_time = datetime.strptime(req_time, date_format)
                diff = (retry_after_time - req_time).total_seconds()
                sleep(diff + 0.5)
                # print("DIFFERENCE: ", diff)
        else: 
            sleep(3)

        # wait_time = (retry_after_time - req_time).total_seconds()
        
        # poll whether cert is issued - POST-as-GET

        poll_for_cert_status_res = poll_certificate_status(replay_nonce=csr_res.headers["Replay-Nonce"], order_url=order_url)
        certificate_url = poll_for_cert_status_res.json()["certificate"]


        cert_dwnld_res = download_certificate(poll_for_cert_status_res.headers["Replay-Nonce"], certificate_url=certificate_url)
        cert_content = cert_dwnld_res.content

        # save cert in file
        save_certificate(domain_key=domain_key, cert_path="./my_certificate.pem", domain_key_path="./domain_key.pem")

        # create HTTPS server #TODO: see if this actually works for what you need
        
        my_server = start_certificate_server(certfile="./my_certificate.pem", keyfile="./domain_key.pem", path_to_ca=path_to_ca)

        

        # IF REVOKE IS SET, IMMEDIATELY REVOKE CERT
        if final_args.revoke == True:
            revoke_certificate(replay_nonce=curr_nonce, certificate=cert_content)
            # my_server.shutdown()
            # my_server.server_close()
            # os._exit()

            

    else :
        # print('http challenge!!')
        challenges = {}

        for auth_res in auth_responses:
            curr_identifier = auth_res.json()["identifier"]["value"]



            curr_challenges = auth_res.json()["challenges"]
            http_challenge = next((chall for chall in curr_challenges if chall["type"] == "http-01"), None)
            challenges[curr_identifier] = http_challenge

        # print("Challenges (HTTP) from all responses::: ", challenges) 

        # JWK THUMBPRINT 
        jwk_dump = json.dumps({
            "e": jwk["e"],
            "kty": jwk["kty"],
            "n": jwk["n"],
        }, separators=(',', ':')).encode('utf-8')

        jwk_dump_hash = hashlib.sha256(jwk_dump).digest()
        jwk_thumbprint = base64url(jwk_dump_hash)

        for domain in challenges: 
            # FULFILL REQUIREMENTS
            print("curr domain:: ", domain)
            myDNS01Handler.put_dnsRecord(domain, "0.0.0.0")
            # myDNS01Handler.put_dnsRecord(domain + ".", "0.0.0.0")
            # myDNS01Handler.put_dnsRecord("." + domain, "0.0.0.0")

            # print("curr domain:: ", domain)
            token = challenges[domain]["token"] # (there really is only one challenge object behind each domain key)
            challenge_url = challenges[domain]["url"]
            
            key_authorization = f"{token}.{jwk_thumbprint}"
            key_auth_ASCII = key_authorization.encode('ascii')

            new_path = "./.well-known/acme-challenge/" + token
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            # if not os.path.exists(new_path):
            #     os.makedirs(new_path)
            print("made directory!!!!!!")

            
            
            with open(new_path, "wb") as challenge_file:
                challenge_file.write(key_auth_ASCII) # or just key auth

            
            


            # construct ready-to-validate-challenges request 

            challenge_validate_req = send_challenge_validate(curr_nonce, challenge_url)
            curr_nonce = challenge_validate_req.headers["Replay-Nonce"] 
            # retry_after_time = challenge_validate_req.headers["Retry-After"]


            # TODO: retry after time


        sleep(4) #maybe remove this aswell??



        # POLL FOR STATUS OF CHALLENGES
        for domain in challenges.keys():
            poll_for_status_res = poll_order(replay_nonce=curr_nonce, order_url=order_url)


        curr_nonce = poll_for_status_res.headers["Replay-Nonce"]

        
        ## CONSTRUCT & SEND CSR

        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr_res = send_CSR(curr_nonce, finalize_url, [domain for domain in challenges], domain_key)

        # WAIT TILL YOU POLL CERTIFICATE STATUS
        if "Retry-After" in csr_res.headers:
            
            retry_after_time = csr_res.headers["Retry-After"]
            if retry_after_time.isdigit():
                print(" DIGIIIIIIIIIIIIIIT :::!!!!!!!! INT INT INT INT ITN INT  ")
                sleep(int(retry_after_time) + 0.5)

            else :
                date_format = '%a, %d %b %Y %H:%M:%S %Z'
                req_time = csr_res.headers["Date"]
                retry_after_time = datetime.strptime(retry_after_time, date_format)
                req_time = datetime.strptime(req_time, date_format)
                diff = (retry_after_time - req_time).total_seconds()
                sleep(diff + 0.5)
                # print("DIFFERENCE: ", diff)
        else: 
            print(" RETRY AFTER NOT IN HEADER!!!! ")
            # sleep(3) 

        # wait_time = (retry_after_time - req_time).total_seconds()
        
        # POLL CERTIFICATE STATUS (POST-as-GET)

        poll_for_cert_status_res = poll_certificate_status(replay_nonce=csr_res.headers["Replay-Nonce"], order_url=order_url)
        certificate_url = poll_for_cert_status_res.json()["certificate"]

        # DOWNLOAD AND SAVE CERTIFICATE
        cert_dwnld_res = download_certificate(poll_for_cert_status_res.headers["Replay-Nonce"], certificate_url=certificate_url)
        cert_content = cert_dwnld_res.content


        # SAVE cert in file
        save_certificate(domain_key=domain_key, cert_path="./my_certificate.pem", domain_key_path="./domain_key.pem")
        

        
        # CREATE HTTPS server #TODO: see if this actually works for what you need     
        my_server = start_certificate_server(certfile="./my_certificate.pem", keyfile="./domain_key.pem", path_to_ca=path_to_ca)


        # IF REVOKE IS SET, IMMEDIATELY REVOKE CERT
        if final_args.revoke == True:
            curr_nonce = revoke_certificate(replay_nonce=curr_nonce, certificate=cert_content)
            # my_server.shutdown()
            # my_server.server_close()
            # os._exit()



    print("-END OF MAIN CODE- Response to CERT poll::: ", poll_for_cert_status_res) 
