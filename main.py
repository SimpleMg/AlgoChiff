
class Encrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.message = self.splitMessage(message)
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[0] = self.key.deriveKeys(self.key.keyBase[0], 5)
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16)
        self.key.keys[2] = self.key.deriveKeys(self.key.keyBase[2], 5)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)


    def splitMessage(self, bits) -> list:
        pass





def argument() -> None:
    argParser = ArgumentParser()
    argParser.add_argument("-f", "--file", help="File with message")
    argParser.add_argument("-k", "--key", help="Encryption key")
    argParser.add_argument("-m", "--mode", help="Encrypt (E) / Decrypt (D)")
    args = argParser.parse_args()
    assert args.key, "Miss the KEY (512 bits) with --key <key>"
    KEY = Key(args.key)
    assert args.file, "Miss file path with --file <path>"
    message = open(args.file, 'r').read()
    mode = 1 if args.mode == 'D' else 0


if __name__ == '__main__':
    print(argument())
