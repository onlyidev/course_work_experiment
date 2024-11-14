#!/bin/bash

python main.py 64 32 300 data/malware.npy data/benign.npy --detector MultiLayerPerceptron --gen-hidden-sizes 256 128 256 512 1024