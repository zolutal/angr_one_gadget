
from an_gadget import AngrWrapper, CapstoneWrapper 
import sys

def get_basic_gadgets(libc_path: str):
    libc_path = sys.argv[1]
    
    angr: AngrWrapper = AngrWrapper(libc_path)
    cs: CapstoneWrapper = CapstoneWrapper(libc_path)

    min_addr: int = angr.text_section.min_addr
    memsize: int = angr.text_section.memsize
    disas_dict, addresses = cs.get_disassembly(min_addr, memsize)

    xref_idxs = cs.get_xref_idx(disas_dict, addresses, angr.binsh_addr)
    candidate_idxs = cs.get_basic_candidates(disas_dict, addresses, xref_idxs, angr.execve_addr)

    constr, addr = angr.get_satisfiable_candidates(candidate_idxs, addresses)

    print("Found Gadgets:")
    for i in range(len(constr)):
        print("Address:", hex(addr[i]))
        pconstr = angr.printable_constraints(constr[i])
        print(pconstr)