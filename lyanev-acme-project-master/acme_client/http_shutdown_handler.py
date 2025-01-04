from http.server import BaseHTTPRequestHandler
import os, sys

class HTTPShutdownHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        
        # self.wfile.write(content)

        print("--------------SHUTDOWN HANDLER-------------------")
        print("RECEIVED PATH:: ", self.path)

        if self.path == '/shutdown':
            print('shutting down... from if')
            # print(10/0)
            os._exit(1)

        # maybe here depending on path or incoming request 
        # search for the given path in local directory
        # request_path = "." + self.path + "/index.html"
        
        # content = ""
        # with open(request_path, "rb") as challenge_file:
        #     content = challenge_file.read().decode('ascii')

        # print('content read from file: ..', content)

        self.send_response(200)
        # self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        # or maybe write in antoher way
    


        





# If the request was mapped to a directory, the directory is checked for a file
# named index.htm(l). If found, the file’s contents are returned;
