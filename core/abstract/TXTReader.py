from core.abstract.Reader import Reader, TYPE_BYTE


class TXTReader(Reader):
    def __init__(self, path):
        super().__init__(path)
        self.text_arr = self.create_text_arr()

    def create_text_arr(self):
        path = self.path
        f = open(path, 'r', encoding="utf8")
        try:
            text_arr = f.readlines()
        except UnicodeDecodeError as e:
            f.close()
            self.type = TYPE_BYTE
            f = open(path, 'rb')
            text_arr = f.readlines()

        return text_arr
