#!/bin/bash

API_KEY=$(<api.key)
DOMAIN="https://virusshare.com/apiv2/download?apikey=${API_KEY}"
PARAM_NAME="hash"

wget "${DOMAIN}&${PARAM_NAME}=$1" -P $2