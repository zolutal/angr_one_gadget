__version__ = "0.0.1"

import sys
from .angrwrapper import AngrWrapper
from .capstonewrapper import CapstoneWrapper
from .an_gadget import get_basic_gadgets
from .cli import run

def main():
    run(sys.argv[1:])