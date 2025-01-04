from dnslib import RR, QTYPE

class DNS01Handler:
    def __init__(self, defaultAResponse):
        self.dnsRecords = {}
        self.defaultAResponse = defaultAResponse

    def put_dnsRecord(self, domain, value):
        # here domain already includes _acme-challenge prepended
        self.dnsRecords[domain] = value

    def resolve(self, request, handler):
        reply = request.reply()

        
        print("--- current status of RECORDS::: ", self.dnsRecords)

        req_domain = str(request.q.qname) # again with _acme-challenge in front (if for challenge)
        
        question = request.q

        print(question.qname, " ", QTYPE[question.qtype], " ", question.qclass)
        
        # print("REQ DOMAIN NAME:::::::  ", req_domain, " TYPE:: ", QTYPE[request.q.qtype])

        # maybe do some manipulation on domain name, 
        base_req_domain = req_domain.replace('_acme-challenge.', '')
        base_req_domain = base_req_domain.rstrip(".")
        # print("BASE REQ DOMAIN::: ", base_req_domain)
        # then figure out base,
        # then for all keys that contain the base (trivially includes base)
        # add an answer


        # print("REQUEST QTYPE :::", QTYPE[request.q.qtype])
        # print("DNS QUESTION.... ", request.q.qclass)
        # print("REQUESTED QTYPE :::::::  ", QTYPE[request.q.qtype])
        # print("KEYS LISTTTT ", self.dnsRecords.keys())
        # if req_domain in list(self.dnsRecords.keys()): 
        #    print("req_domain in ..!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        if (QTYPE[request.q.qtype] == "TXT" and req_domain in list(self.dnsRecords.keys())): # or maybe dns question? cause no qname found
            # print(":::::::::::::::::::::::::::RECORD FOUND:::::::::::: ")

            # for every domain in keys that contains the req_domain, do 
            for domain in self.dnsRecords:
                if base_req_domain in domain:
                    # print("ADDING RECORD TO DNS!!!")
                    if 'WILDCARD_' in domain:
                        reply.add_answer(*RR.fromZone(req_domain.replace('WILDCARD_', '') + f" 300 IN TXT \"{self.dnsRecords[domain]}\"")) #maybe remove IN (and maybe add dot at start)
                    else:
                        reply.add_answer(*RR.fromZone(req_domain + f" 300 IN TXT \"{self.dnsRecords[domain]}\""))
        else: 
            
            # print("ENTERED ELSE: RESOLVING FOLLOWING REQUEST::: ", request)
            req_domain_pruned = req_domain.rstrip('.')
            if(req_domain_pruned in list(self.dnsRecords.keys())):
                print("entered 0.0.0.0....")
                reply.add_answer(*RR.fromZone(f"{req_domain_pruned} 300 IN A \"{self.defaultAResponse}\""))
            else: 
                print("...entered default response")
                if(QTYPE[request.q.qtype] == "A"):
                    reply.add_answer(*RR.fromZone(f"{req_domain} 300 IN A {self.defaultAResponse}"))  
                else:
                    reply.add_answer(*RR.fromZone(f"{req_domain} 300 IN AAAA {self.defaultAResponse}"))  

            
            # print("REPLY::: ", reply)

        return reply
