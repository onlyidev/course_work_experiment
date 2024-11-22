import vt
import os
import time
from dotenv import load_dotenv

load_dotenv()

client = vt.Client(os.getenv("VIRUS_TOTAL_API"))

def loadDir(path: str) -> list:
    print(f"Loading files from {path}")
    dir = os.listdir(path)
    filteredDir = list(filter(lambda x: not x.startswith("download") and not os.path.isdir(os.path.join(path, x)), dir))
    return [os.path.join(path, file) for file in filteredDir]

for idx, sample in enumerate(loadDir("lk_dataset/data/obfuscated")):
  print(f"Scanning {sample}...")
  with open(sample, "rb") as f:
    analysis = client.scan_file(f)