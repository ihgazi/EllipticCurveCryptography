#!/usr/bin/python3

"""
"" 18th OCT 2025 ::: Irfan Habeeb Gazi
""
"" Usage: sage KeyGenerationUtil.py <Arguments>
""
"" This utility program uses KeyGeneration.py to generate the public / private key pairs for an
"" Elliptic Curve Cryptography system, and saves them to two seperate files in the current
"" working directory, 'ecc_public_key.txt' and 'ecc_private_key.txt'.
""
"" The arguments to be provided to the program are the same as those required by KeyGeneration.py
"" Please refer to the documentation of KeyGeneration.py for more details.
"""

import json
from KeyGeneration import generate_keypair


def write_key_files_json(mode, args, pub_filename="ecc_public_key.txt", priv_filename="ecc_private_key.txt"):
    params = generate_keypair(mode, args)
    # Write public key data as JSON
    coefficients = params['curve'].a_invariants()
    field_order = params['field'].order()
    field_degree = params['field'].degree()

    pub_data = {
        "public_key": str(params['public_key']),
        "generator": str(params['generator']),
        "coefficients": str(coefficients),
        "field_order": str(field_order),
        "field_degree": str(field_degree),
    }
    with open(pub_filename, 'w') as pub_file:
        json.dump(pub_data, pub_file, indent=2)
    # Write private key data as JSON
    priv_data = {
        "private_key": str(params['private_key'])
    }
    with open(priv_filename, 'w') as priv_file:
        json.dump(priv_data, priv_file, indent=2)


if __name__ == "__main__":
    import sys
    mode = int(sys.argv[1])
    args = sys.argv[2:]
    write_key_files_json(mode, args)
