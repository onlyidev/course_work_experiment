import lief
import pickle
import typing
import os
import logging
import numpy as np

class FeatureExtractor:
    def __init__(self):
        self.db = set()
    
    def parseAPIs(self, path: str) -> typing.List[typing.Tuple[str, str]]:
        pe = lief.parse(path)
        arr = []
        for lib in pe.imports:
            for func in lib.entries:
                arr.append((lib.name, func.name))
                self.db.add((lib.name, func.name))
        arr.sort()
        return arr
            
    def getAPIs(self, db = None) -> typing.List[str]:
        db = self.db if db is None else db
        apiList = [api for _,api in db]
        apiList.sort()
        return apiList
    
    def save(self, path: str, obj = None) -> None:
        with open(path, "wb") as f_out:
            pickle.dump(self if obj is None else obj, f_out)

    def getLatentMatrix(self, path):
        files = self.loadDir(path)
        [self.parseAPIs(file) for file in files] # Load to db
        return np.array([self.__generateLatentVector(file) for file in files])

    def __generateLatentVector(self, path: str):
        features = self.getAPIs(self.parseAPIs(path))
        return np.array([x in features for x in self.getAPIs()], dtype=np.int8)

    @staticmethod
    def loadDir(path) -> typing.List[str]:
        print(f"Loading files from {path}")
        dir = os.listdir(path)
        filteredDir = list(filter(lambda x: not x.startswith("download"), dir))
        return [os.path.join(path, file) for file in filteredDir]
    
    @staticmethod
    def checkValidPE(path: str) -> bool:
        if lief.is_pe(path):
            try:
                return lief.parse(path).has_imports
            except:
                logging.error(f"Error parsing file {path}")
                return False
        return False