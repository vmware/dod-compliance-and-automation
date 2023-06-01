#!/bin/bash
key=$(head -c 32 /dev/urandom | base64 |  sed 's/\//\\\//g')
sed -i.bak "s/mykey/$key/g" /etc/kubernetes/encryption-config.yaml
