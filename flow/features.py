import numpy as np
import lief
import os
from typing import List, Tuple
from malgan._log_tools import logging

class Features:
    def __init__(self, fullList: dict) -> None:
        self.full = list(fullList)
        self.full.sort()
        self.pathList = list()

    def _parseAPIs(self, path: str) -> List[Tuple[str, str]]:
        pe = lief.parse(path)
        arr = []
        for lib in pe.imports:
            for func in lib.entries:
                arr.append(self.tupleToStr((lib.name, func.name)))
        arr.sort()
        self.pathList.append(path)
        return arr
    
    @staticmethod
    def tupleToStr(t: Tuple[str, str]) -> str:
        return f"{t[0]}/{t[1]}"

    def createEncoding(self, samplePath: str) -> np.ndarray:
        apis = self._parseAPIs(samplePath)
        return np.array([1 if f in apis else 0 for f in self.full])
    
    def reverseEncoding(self, encoding: np.ndarray) -> List[Tuple[str,str]]:
        idx = np.where(encoding == 1)[0]
        return [tuple(self.full[i].split("/", 1)) for i in idx]

    def _saveAE(self, pe, idx: int, dirPath: str):
        b = lief.PE.Builder(pe)
        b.build_imports(True)
        b.patch_imports(True)
        b.build()
        b.write(os.path.join(dirPath, f"{idx}"))

    def obfuscate(self, prefix, encodings: np.ndarray, dirPath: str) -> None:
        for i, encoding in enumerate(encodings): 
            libs = self.reverseEncoding(encoding)
            pe = lief.parse(list(self.pathList)[i])
            logging.info("Adding libraries...")
            for lib,func in libs:
                if lib not in [pelib.name for pelib in pe.imports]:
                    new_lib = pe.add_library(lib)
                else:
                    new_lib = next(pelib for pelib in pe.imports if pelib.name == lib)

                new_lib.add_entry(func)
            logging.info("Saving...")
            self._saveAE(pe, f"{prefix}_{i}", dirPath)