import lief
import pickle
import typing
import os
import logging

class FeatureExtractor:
    def __init__(self):
        self.db = set()
    
    def parseAPIs(self, path: str) -> None:
        pe = lief.parse(path)
        for lib in pe.imports:
            for func in lib.entries:
                self.db.add((lib.name, func.name))
            
    def getAPIs(self) -> typing.List[str]:
        apiList = [api for _,api in self.db]
        apiList.sort()
        return apiList
    
    def save(self, path: str) -> None:
        with open(path, "wb") as f_out:
            pickle.dump(self.db, f_out)
        
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