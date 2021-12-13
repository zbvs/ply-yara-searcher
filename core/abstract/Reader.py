TYPE_STRING = "TYPE_STRING"
TYPE_BYTE = "TYPE_BYTE"


class Reader:
    def __init__(self, path):
        self.path = path
        self.text_arr = []
        self.type = TYPE_STRING

    def create_text_arr(self):
        raise NotImplementedError(f"[{self.__class__.__name__}] not implemented {self.create_text_arr.__name__}")
