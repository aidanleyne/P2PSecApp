import socket
from zeroconf import Zeroconf

class ServiceListener:
    def __init__(self, discovery_instance):
        self.conf = Zeroconf()
        self.discovery = discovery_instance

    def add_service(self, zeroconf, type_, name):
        info = zeroconf.get_service_info(type_, name)
        if info:
            if 'SecureMsgService' in name:
                print(f'Found messaging service: {info.name}')
                self.discovery.connect({'host': info.parsed_addresses()[0], 'port': info.port})
                return
            else:
                print(f'Discovered non-messaging service: {info.name}')

    def update_service(self, zeroconf, type_, name, state_change):
        pass