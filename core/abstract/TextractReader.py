import textract

from core.abstract.Reader import Reader


def str_to_hex(str):
    result = ''
    for i in range(0, len(str)):
        result += ('%x ' % ord(str[i]))
    return result


class TextractReader(Reader):
    def __init__(self, path):
        super().__init__(path)
        self.text_arr = self.create_text_arr()

    def create_text_arr(self):
        text = textract.process(self.path, input_encoding='utf_8')
        text = text.decode("utf-8")
        return text.splitlines()
