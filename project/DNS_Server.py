import copy

from dnslib import RR
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

# SOURCE CODE FROM DNSLIB 

class FixedResolver(BaseResolver):
    def __init__(self, zone, url):

        self.rrs = RR.fromZone(zone)
        self.url = url

    def resolve(self, request, handler):

        reply = request.reply()

        for rr in self.rrs:
            a = copy.copy(rr)
            reply.add_answer(a)

        return reply

class DNS_Server(object):

    def __init__(self, zone, ipv4_address, udp_port):

        self.zone = zone
        self.ipv4_address = ipv4_address
        self.udp_port = udp_port

        self.server = DNSServer(FixedResolver(self.zone, None), address=self.ipv4_address, port=self.udp_port)
        
    def start(self):
        self.server.start_thread()

    def stop(self):
        self.server.stop()
    
    def start_challenge_mode(self, challenge_zone, challenge_url):
        self.stop()
        self.server = DNSServer(FixedResolver(challenge_zone, challenge_url), address=self.ipv4_address, port=self.udp_port)
        self.start()
    
    def stop_challenge_mode(self):
        self.stop()
        self.server = DNSServer(FixedResolver(self.zone, None), address=self.ipv4_address, port=self.udp_port)
        self.start()