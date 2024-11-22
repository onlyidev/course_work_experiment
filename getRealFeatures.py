from malgan import MalGAN, BlackBoxDetector, MalwareDataset, setup_logger, logging
import torch 
from typing import Union
import pickle
import numpy as np
from pathlib import Path
from torch import nn
import matplotlib.pyplot as plt
import os
from flow.features import Features
import ast
import pandas as pd
import lief


def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def loadDir(path: str) -> list:
    print(f"Loading files from {path}")
    dir = os.listdir(path)
    filteredDir = list(filter(lambda x: not x.startswith("download") and not os.path.isdir(os.path.join(path, x)), dir))
    return chunk([os.path.join(path, file) for file in filteredDir], 32)

batchedSamples = loadDir("lk_dataset/data/malware")

arr = []
for samples in batchedSamples:
    for sample in samples:
        p = lief.parse(sample)
        for lib in p.imports:
            arr.append({lib.name: [func.name for func in lib.entries]})