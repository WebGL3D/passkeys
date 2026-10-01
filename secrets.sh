#!/bin/bash

# Generate the keys
openssl genpkey -out auth_private_key.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048
openssl rsa -in auth_private_key.pem -pubout -out auth_public_key.pem

# Save the keys on disk, for running locally
# This shouldn't match what's in cloud, you can generate the keys again before running this
echo "ORIGIN=\"http://localhost:8787\"\nJWT__PRIVATE_KEY=\"$(cat auth_private_key.pem)\"\nJWT__PUBLIC_KEY=\"$(cat auth_public_key.pem)\"" > .dev.vars
