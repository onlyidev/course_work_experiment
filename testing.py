from lk_dataset.feature_extractor import FeatureExtractor

fe = FeatureExtractor()

l = [fe.parseAPIs(x) for x in fe.loadDir("./lk_dataset/data")]
# l = [x for x in fe.loadDir("./lk_dataset/data") if fe.checkValidPE(x)]

print(len(fe.getAPIs()))