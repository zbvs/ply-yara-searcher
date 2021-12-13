# -*- coding: utf-8 -*-
import platform
import re

from core.abstract.HWPReader import HWPReader
from core.abstract.Reader import TYPE_STRING
from core.abstract.TXTReader import TXTReader
from core.abstract.TextractReader import TextractReader
from core.path_util import get_extension

OS_PLATFORM = platform.system()


def str_to_hex(str):
    result = ''
    for i in range(0, len(str)):
        result += ('%x ' % ord(str[i]))
    return result


creator_dict = {}

if OS_PLATFORM == 'Linux':
    creator_dict['pdf'] = TextractReader
    creator_dict['png'] = TextractReader
    creator_dict['jpg'] = TextractReader
    creator_dict['jpeg'] = TextractReader
    creator_dict['tiff'] = TextractReader
    creator_dict['gif'] = TextractReader
    creator_dict['mp3'] = TextractReader
    creator_dict['wav'] = TextractReader
    creator_dict['ogg'] = TextractReader

#creator_dict['doc'] = TextractReader
creator_dict['docx'] = TextractReader
creator_dict['eml'] = TextractReader
creator_dict['epub'] = TextractReader
creator_dict['pptx'] = TextractReader
creator_dict['psv'] = TextractReader
creator_dict['rtf'] = TextractReader
creator_dict['xlsx'] = TextractReader
creator_dict['xls'] = TextractReader

creator_dict['c'] = TXTReader
creator_dict['cxx'] = TXTReader
creator_dict['cpp'] = TXTReader
creator_dict['h'] = TXTReader
creator_dict['hpp'] = TXTReader
creator_dict['py'] = TXTReader
creator_dict['js'] = TXTReader
creator_dict['ts'] = TXTReader
creator_dict['java'] = TXTReader
creator_dict['xml'] = TXTReader
creator_dict['html'] = TXTReader

creator_dict['json'] = TXTReader
creator_dict['txt'] = TXTReader

creator_dict['hwp'] = HWPReader




class NotSupportedTypeException(Exception):
    pass


class AbstractFile:
    def __init__(self, root, file):
        self.type = TYPE_STRING
        self.root = root
        self.file = file
        path = root + file
        self.path = path
        self.file_extension = get_extension(self.path)
        if self.file_extension not in creator_dict:
            raise NotSupportedTypeException(f"file extension {self.file_extension} not supported in " + OS_PLATFORM)

        reader = creator_dict[self.file_extension](path)
        self.text_arr = reader.text_arr

    def count_string(self, src):
        total_cnt = 0
        src = src.lower()
        for i in range(0, len(self.text_arr)):
            try:
                cnt = self.text_arr[i].lower().count(src.lower())
            except:
                continue
            total_cnt += cnt
        return total_cnt

    def regex_search(self, regex_rule):
        if self.type == TYPE_STRING:
            contents = "\n".join(self.text_arr)
        else:
            contents = b"\n".join(self.text_arr)
        return re.search(regex_rule, contents)
