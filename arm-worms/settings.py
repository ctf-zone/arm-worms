import binascii
import os

BASE_DIR = os.path.dirname(__file__)

VIS_HOST = '0.0.0.0'

TEAMS = {
    '1': 'mslc',
    '2': 'mhackeroni',
    '3': 'A*0*E',
    '4': 'perfect blue',
    '5': 'Bushwhackers',
    '6': '地松鼠.PAS',
    '7': 'Dragon Sector',
    '8': 'Tea Deliverers',
    '9': 'p4',
    '10': 'TSG'
}

MEMORY_SIZE = 4096
SHELLCODE_SIZE = 1024
STACK_SIZE = 1024
DATA_SIZE = 2048

X86_MINING_SCORE = 1
ARM_MINING_SCORE = 2
SUPER_MINING_SCORE = 4

MAX_COMPUTER_ITERATIONS = 2**17
MAX_TIME = 120

MAP_FILE = '_armworms_map.json'
REPLAY_FILE = '_armworms_replay.json'
SCORE_FILE = '_armworms_score.json'

DEFAULT_SHELLCODE = 'b8b0000000cd805731f689f7b8ffff0000b90000000089fa81e2ff00000089d3eb2489c231da83e20185d2740e89c2d1ea81f20884000089d0eb02d1e889ca83c20188d1d1eb83f90776d7f7d089c289d389c289d1c1e10889dac1ea0881e2ff00000009ca89d089c281e2ffff00005f39fa57740583c601eb9056b8b2000000cd80be00080000668b5e0231d2668b56046683fb04740583fb017417bf00000000b900010000b8b30000005bcd80e94dffffffeb005fb8b1000000cd80e93effffff'
