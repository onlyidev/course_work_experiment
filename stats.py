import vt
import os
import pandas as pd
import pickle
from dotenv import load_dotenv

load_dotenv()

client = vt.Client(os.getenv("VIRUS_TOTAL_API"))

df = pd.read_csv("lk_dataset/data/df.csv")
analyses = []

def analyzeInVT(sha):
    print(f"Analyzing {sha}...")
    analysis = client.get_object(f"/files/{sha}")
    analyses.append(analysis)
    return analysis.last_analysis_stats["undetected"]
try:
    if not "undetected_malware" in df.columns:
        df["undetected_malware"] = df["malware"].apply(analyzeInVT)
    df.to_csv("lk_dataset/data/df.csv", index=False)
    if not "undetected_obfuscated" in df.columns:
        df["undetected_obfuscated"] = df["obfuscated"].apply(analyzeInVT)
    df.to_csv("lk_dataset/data/df.csv", index=False)
except:
    print("Error")
    df.to_csv("err.csv", index=False)
finally:
    with open("analyses.pkl", "wb") as f:
        pickle.dump(analyses, f)