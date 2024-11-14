import vt
import os
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

client = vt.Client(os.getenv("VIRUS_TOTAL_API"))

df = pd.read_csv("lk_dataset/data/df.csv")

def analyzeInVT(sha):
    print(f"Analyzing {sha}...")
    analysis = client.get_object(f"/files/{sha}")
    return analysis.last_analysis_stats["undetected"]

if not "undetected_malware" in df.columns:
    df["undetected_malware"] = df["malware"].apply(analyzeInVT)
df.to_csv("lk_dataset/data/df.csv", index=False)
if not "undetected_obfuscated" in df.columns:
    df["undetected_obfuscated"] = df["obfuscated"].apply(analyzeInVT)
df.to_csv("lk_dataset/data/df.csv", index=False)