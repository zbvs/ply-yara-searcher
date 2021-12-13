import logging
import os
import re
import zlib
from zipfile import BadZipFile

from core.abstract.AbstractFile import AbstractFile, NotSupportedTypeException
from core.path_util import normalize_root_path, get_extension


class Searcher:
    def __init__(self, dir_path, path_regex, extensions):
        self.dir_path = dir_path
        self.path_regex = path_regex
        self.extensions = extensions
        self.abstract_file = None

    def is_target_extension(self, extension):
        if self.extensions is not None:
            return extension in self.extensions
        return True

    def execute(self):
        for root, dirs, files in os.walk(self.dir_path):
            root = normalize_root_path(root)

            for file in files:
                extension = get_extension(file)
                if not self.is_target_extension(extension):
                    continue

                filepath = root + file
                if self.path_regex is not None and re.match(self.path_regex, filepath) is None:
                    continue

                try:
                    self.abstract_file = AbstractFile(root, file)
                except (NotSupportedTypeException) as e:
                    logging.debug(filepath + ": " + str(e))
                    continue
                except (BadZipFile, zlib.error) as e:
                    logging.warning(filepath + ": " + str(e))

                result = self.execute_one()
                if result:
                    print(filepath)

    def execute_one(self):
        raise NotImplementedError(f"[{self.__class__.__name__}] not implemented {self.execute_one.__name__}")
