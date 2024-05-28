# generate_features.py

import hashlib
import random

def generate_placeholder_features():
    features = {
        "FileName": "0124e21d-018c-4ce0-92a3-b9e205a76bc0.dll",
        "md5Hash": hashlib.md5(b"0124e21d-018c-4ce0-92a3-b9e205a76bc0.dll").hexdigest(),
        "Machine": 332,
        "DebugSize": 0,
        "DebugRVA": 0,
        "MajorImageVersion": 0,
        "MajorOSVersion": 4,
        "ExportRVA": 0,
        "ExportSize": 0,
        "IatVRA": 8192,
        "MajorLinkerVersion": 8,
        "MinorLinkerVersion": 0,
        "NumberOfSections": 3,
        "SizeOfStackReserve": 1048576,
        "DllCharacteristics": 34112,
        "ResourceSize": 672,
        "BitcoinAddresses": generate_random_bitcoin_addresses(), # Placeholder for Bitcoin addresses
        "Benign": 1
    }
    return features

def generate_random_bitcoin_addresses():
    # Generating random Bitcoin addresses for demonstration purposes
    bitcoin_addresses = []
    for _ in range(random.randint(1, 5)):
        address = ''.join(random.choices('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', k=34))
        bitcoin_addresses.append(address)
    return bitcoin_addresses

if __name__ == "__main__":
    features = generate_placeholder_features()
    print(features)
