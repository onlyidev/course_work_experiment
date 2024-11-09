from lk_dataset.feature_extractor import FeatureExtractor
import numpy as np

fe = FeatureExtractor()

# l = [fe.parseAPIs(x) for x in fe.loadDir("./lk_dataset/data")]
# l = [x for x in fe.loadDir("./lk_dataset/data") if fe.checkValidPE(x)]

# print(fe.getAPIs())
m = fe.getLatentMatrix("./lk_dataset/data")
print(m)
np.save("malware.npy", m)