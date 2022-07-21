# TODO argparse
from an_gadget import get_basic_gadgets

def run(argv):
    if len(argv) != 1 or argv[0] in ['-h', '--help']:
        print("Usage: python angr_one </path/to/libc>")
        exit()
    get_basic_gadgets(argv[0])