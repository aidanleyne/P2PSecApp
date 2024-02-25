class User:
    def __init__(self, uname, passwd='', pubk='', privk=''):
        self.username = uname
        self.password = passwd
        self.public_key, self.private_key = self.key_gen()
        self.contacts = []

    def add_contact(self, uname, public_key):
        self.contacts.append(User(uname, public_key))
    
    def set_private_key(self, nkey):
        self.private_key = nkey

    def set_private_key(self, nkey):
        self.public_key = nkey

def main():
    return

if __name__ == "__main__":
    main()