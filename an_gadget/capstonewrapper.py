
from collections import OrderedDict
from typing import List, Tuple

import capstone

class CapstoneWrapper():
    def __init__(self, libc_path: str):
        self.mi: capstone.Cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.mi.skipdata = True
        self.libc_path: str = libc_path

    def get_disassembly(self, offset: int, memsize: int) -> Tuple[dict, List[int]]:
        libc_fd: int = open(self.libc_path, 'rb')
        libc_fd.seek(offset)
        libc_bin: bytes = libc_fd.read(memsize)


        instr_dict: OrderedDict = OrderedDict()
        addresses: list[int] = []
        for (address, size, mnemonic, op_str) in self.mi.disasm_lite(libc_bin, offset):
            instr_dict[address] = {'mnemonic': mnemonic, 'op_str': op_str, 'size': size}
            addresses.append(address)

        return instr_dict, addresses


    def get_xref_idx(self, disas_dict: dict, addresses: List[int], bin_sh_addr: int) -> List[int]:
        xrefs: List[int] = []
        for i in range(len(addresses)):
            v = disas_dict[addresses[i]]
            if v['mnemonic'] == 'lea':
                if hex(bin_sh_addr - addresses[i] - v['size']) in v['op_str']:
                    xrefs.append(i)
        return xrefs


    def get_basic_candidates(self, disas_dict, addresses, xrefs, execve_addr) -> List[int]:
        candidates: List[int] = []
        xref: int
        for xref in xrefs:
            for i in range(1,8):
                instr: str = disas_dict[addresses[xref+i]] 
                if instr['mnemonic'] == 'call' and hex(execve_addr) in instr['op_str']:
                    candidates.append(xref) 
                    for j in range(-1,-9,-1):
                        if disas_dict[addresses[xref+j]]['mnemonic'] == 'mov':
                            candidates.append(xref+j)
                        else:
                            break
        return candidates 