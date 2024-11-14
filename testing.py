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


Z=64
h_gen=[256,128,256,512,1024]
h_discrim=[256,256]
g_hidden=nn.LeakyReLU
detector=None#BlackBoxDetector.Type.RandomForest
mal_file="data/malware.npy"
ben_file="data/benign.npy"

def load_dataset(file_path: Union[str, Path], y: int) -> MalwareDataset:
    r"""
    Extracts the input data from disk and packages them into format expected by \p MalGAN.  Supports
    loading files from numpy, torch, and pickle.  Other formats (based on the file extension) will
    result in a \p ValueError.

    :param file_path: Path to a NumPy data file containing tensors for the benign and malware
                      data.
    :param y: Y value for dataset
    :return: \p MalwareDataset objects for the malware and benign files respectively.
    """
    file_ext = Path(file_path).suffix
    if file_ext in {".npy", ".npz"}:
        data = np.load(file_path)
    elif file_ext in {".pt", ".pth"}:
        data = torch.load(str(file_path))
    elif file_ext == ".pk":
        with open(str(file_path), "rb") as f_in:
            data = pickle.load(f_in)
    else:
        raise ValueError("Unknown file extension.  Cannot determine how to import")
    return MalwareDataset(x=data, y=y)


setup_logger(False)


class WithThreshold(nn.Module):
    def __init__(self, base_model, threshold=0.51):
        super(WithThreshold, self).__init__()
        self.base_model = base_model
        self.sigmoid = nn.Sigmoid()
        self.threshold = threshold

    def forward(self, x):
        x = self.base_model(x)
        self.lastConfidence = self.base_model.confidence(x[1])
        return (x[1] > self.threshold).int()

    def load(self, path):
        self.base_model.load(path)

malgan = WithThreshold(MalGAN(load_dataset(mal_file, MalGAN.Label.Malware.value),
                    load_dataset(ben_file, MalGAN.Label.Benign.value),
                    Z=Z,
                    h_gen=h_gen,
                    h_discrim=h_discrim,
                    g_hidden=g_hidden,
                    detector_type=detector))

# malgan.load("saved_models/malgan_z=128_d-gen=[256,_256]_d-disc=[256,_256]_bs=32_bb=randomforest_g=leakyrelu_final.pth")
# malgan.load("saved_models/malgan_z=128_d-gen=[256,_256]_d-disc=[256,_256]_bs=32_bb=multilayerperceptron_g=leakyrelu_final.pth")
malgan.load("saved_models/malgan_z=64_d-gen=[256,_128,_256,_512,_1024]_d-disc=[256,_256]_bs=32_bb=multilayerperceptron_g=leakyrelu_final.pth")
malgan.eval()

# malwareMatrix = np.load("data/malware.npy")
# v=malwareMatrix[1]
# with torch.no_grad():
#     t=torch.from_numpy(np.array([v])).cuda()
#     r=malgan(t)
#     print(r)

def obfuscate(batch: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        t = torch.from_numpy(batch).cuda()
        r = malgan(t)
        return r.cpu().numpy()

def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def loadDir(path: str) -> list:
    print(f"Loading files from {path}")
    dir = os.listdir(path)
    filteredDir = list(filter(lambda x: not x.startswith("download") and not os.path.isdir(os.path.join(path, x)), dir))
    return chunk([os.path.join(path, file) for file in filteredDir], 32)

def getFileSha(path: str) -> str:
    return os.popen(f"sha256sum -b {path}").read().split(" ", 1)[0]

apis = ast.literal_eval(open("apis", "r").read())
f = Features(apis)

batchedSamples = loadDir("lk_dataset/data/malware")
df = []

logging.info("Encoding...")
for idx, samples in enumerate(batchedSamples):
    logging.info(f"Encoding batch {idx+1}")
    encoding = np.array([f.createEncoding(sample) for sample in samples])
    logging.info("Generating...")
    obfuscated = obfuscate(encoding)
    logging.info("Getting new libs...")
    delta = (encoding ^ obfuscated) & obfuscated
    logging.info("Obfuscating...")
    f.obfuscate(f"batch{idx}", delta, "lk_dataset/data/obfuscated")
    [df.append({"malware": sample, "obfuscated": getFileSha(os.path.join("lk_dataset/data/obfuscated", f"batch{idx}_{i}")), "added_features": delta[i].sum()}) for i, sample in enumerate(samples)]
    logging.info("Done...")

df = pd.DataFrame(df)
df.to_csv("lk_dataset/data/df.csv", index=False)