from zeroconf import Zeroconf

class ServiceListener:
    def __init__(self):
        self.zeroconf = Zeroconf()

    def add_service(self, zeroconf, type_, name):
        info = zeroconf.get_service_info(type_, name)
        if info:
            if 'SecureMsgService' in name:
                print(f'Found messaging service: {info.name}')
                self.connect_to_service(info)
            else:
                print(f'Discovered non-messaging service: {info.name}')

    def connect_to_service(self, service_info):
        # Implement connection logic
        # Create a socket connection to service_info.address and service_info.port
        print(f"Connecting to service {service_info.name} at {service_info.parsed_addresses()[0]}:{service_info.port}")