#!/bin/env python3

import os
import random


# get random data
def get_random_data(length):
    seed = int.from_bytes(os.urandom(8), byteorder='little')
    random.seed(seed)
    alphabet = list(range(256))
    random_string = bytearray(b'')
    for _ in range(length):
        random_string.append(random.choice(alphabet))
    return random_string


# get crc16 value
def crc16(data):
    data = bytearray(data)
    # polynom value
    poly = 0x8408
    # initialize start crc16 value
    crc = 0xffff
    for byte in data:
        crc ^= (0xff & byte)
        for _ in range(8):
            if (crc & 0x0001):
                crc = ((crc >> 1) & 0xffff) ^ poly
            else:
                crc = ((crc >> 1) & 0xffff)
    crc = ~crc
    tmp = crc
    crc = (crc << 8) | (tmp >> 8 & 0xff)
    return (crc & 0xffff)


# get hex data
def dump(data):
    return ' '.join(['{:02x}'.format(byte) for byte in data])
