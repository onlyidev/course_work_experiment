import vt
import os
from dotenv import load_dotenv

load_dotenv()

client = vt.Client(os.getenv("VIRUS_TOTAL_API"))

with open("lk_dataset/data/obfuscated/test_0", "rb") as f:
  analysis = client.scan_file(f)

print(analysis)
