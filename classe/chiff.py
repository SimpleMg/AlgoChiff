
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
