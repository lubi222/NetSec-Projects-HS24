from http.server import BaseHTTPRequestHandler
import os, sys

class HTTPCertHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        
        print("(!!) GETTING HTTPS CERT")
        if self.path == "/":
            
            print("--------------HTTPS CERT HANDLER-------------------")
            print("RECEIVED PATH:: ", self.path)
            # print("curr workig dir", os.getcwd(), " REAL PATH:: ", os.path.realpath(__file__))
            # CWD is lyanev-acme-project, real_path is actually the path to the file


            # DIG OUT THE CERTIFICATE AND SERVE IT!
            with open('./my_certificate.pem', 'rb') as cert_file:
                cert = cert_file.read()

            # read if any intermediates


            
            self.send_response(200)
            # self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Type", "application/pem-certificate-chain")
            # maybe Content-Length as well..
            self.end_headers()
            self.wfile.write(cert)
            # or maybe write in antoher way
        
    # def do_HEAD(self):
    #     print("HEAD!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! REACHED")





# If the request was mapped to a directory, the directory is checked for a file
# named index.htm(l). If found, the file’s contents are returned;
