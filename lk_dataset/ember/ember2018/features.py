import pandas as pd
import ast
import numpy as np
debug = []
df1 = pd.read_csv("./malware.csv")
df2 = pd.read_csv("./benign.csv")
df = pd.concat([df1,df2])


# def createFeaturesVector():
#     s=set()
#     for _,item in df.iterrows():
#         d=ast.literal_eval(item["imports"])
#         [s.add(f"{lib}/{func}") for lib,funcs in d.items() for func in funcs]
#     return s

# s=createFeaturesVector()
# allFeatures = str(s)

# with open("./apis", 'w') as f:
#     f.write(allFeatures)
#     f.close()

# ---

allFeatures = ast.literal_eval(open("./apis", 'r').read())

def createEncoding(sample):
    d=ast.literal_eval(sample)
    s=set([f"{lib}/{func}" for lib,funcs in d.items() for func in funcs])
    return np.array([1 if f in s else 0 for f in allFeatures])

def createFeaturesMatrix(df, path=None):
    m = np.array([createEncoding(sample) for sample in df["imports"]])
    if path is not None:
        np.save(path, m)
    return m

createFeaturesMatrix(df1, "malware.npy")
createFeaturesMatrix(df2, "benign.npy")