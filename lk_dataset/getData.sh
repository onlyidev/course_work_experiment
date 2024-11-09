#!/bin/bash

API_KEY=$(<api.key)
DOMAIN="https://virusshare.com/apiv2/download?apikey=${API_KEY}"
PARAM_NAME="hash"
HASH_FILE="hashes.txt"
DELAY=15              # Delay in seconds (60 seconds / 4 requests)

while read -r hash; do
    wget "${DOMAIN}&${PARAM_NAME}=${hash}" -P ./data/
    
     # Remove the processed hash from the file
    sed -i "1d" "$HASH_FILE"
    sleep "$DELAY"    # Wait to enforce the rate limit
done < "$HASH_FILE"