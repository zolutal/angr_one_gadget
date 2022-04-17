import sys
import angr
import claripy
import os
import subprocess
import capstone
import logging
from collections import OrderedDict

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")


def get_disassembly(libc_path, offset, memsize):
    libc_fd = open(libc_path, 'rb')
    libc_fd.seek(offset)
    libc_bin = libc_fd.read(memsize)

    mi = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    mi.skipdata = True

    instr_dict = OrderedDict()
    addresses = []
    for (address, size, mnemonic, op_str) in mi.disasm_lite(libc_bin, offset):
        instr_dict[address] = {'mnemonic': mnemonic, 'op_str': op_str, 'size': size}
        addresses.append(address)

    return instr_dict, addresses


def get_xref_idx(disas_dict, addresses, bin_sh_addr):
    xrefs = []
    for i in range(len(addresses)):
        v = disas_dict[addresses[i]]
        if v['mnemonic'] == 'lea':
            if hex(bin_sh_addr - addresses[i] - v['size']) in v['op_str']:
                xrefs.append(i)
    return xrefs


def get_basic_candidates(disas_dict, addresses, xrefs, execve_addr):
    candidates = []
    for xref in xrefs:
        for i in range(1,8):
            instr = disas_dict[addresses[xref+i]] 
            if instr['mnemonic'] == 'call' and hex(execve_addr) in instr['op_str']:
                candidates.append(xref) 
                for j in range(-1,-9,-1):
                    if disas_dict[addresses[xref+j]]['mnemonic'] == 'mov':
                        candidates.append(xref+j)
                    else:
                        break
    return candidates 


def hook_exec(state):
    #TODO find memory access constraint fix
    #rsi_mem = state.memory.load(state.regs.rsi, 8) 
    #rdx_mem = state.memory.load(state.regs.rdx, 8) 
    
    state.solver.add(state.regs.rdi == state.globals["binsh_addr"])
    state.solver.add(state.regs.rsi == 0)#, rsi_mem == 0)
    state.solver.add(state.regs.rdx == 0)#, rdx_mem == 0)

    state.globals["sat"] = state.satisfiable()


def printable_constraints(constraints):
    printable = ""
    for c in constraints:
        split_con = str(c)[1:-1].split(" ")
        for i in range(len(split_con)):
            if "reg_" in split_con[i]:
                split_con[i] = split_con[i].split("_")[1]
            if split_con[i] in ["Bool"]:
                split_con[i] = ""
        printable += " ".join(split_con)
        printable += ", "
    return printable[:-2]

def main(libc_path):
    proj = angr.Project(libc_path, auto_load_libs=False, main_opts={'base_addr':0x0})
    text_section = proj.loader.main_object.sections_map['.text']

    disas_dict, addresses = get_disassembly(libc_path, text_section.min_addr, text_section.memsize)

    binsh_addr = list(proj.loader.main_object.memory.find(b"/bin/sh"))[0]
    execve_addr = proj.loader.main_object.get_symbol('execve').relative_addr

    xref_idxs = get_xref_idx(disas_dict, addresses, binsh_addr)
    candidate_idxs = get_basic_candidates(disas_dict, addresses, xref_idxs, execve_addr)

    proj.hook_symbol('execve', hook_exec)

    valid_constr = []
    valid_addr = []
    for cand_idx in candidate_idxs:
        cand = addresses[cand_idx]
        init_state = proj.factory.blank_state(
                addr = cand
        )
        sim = proj.factory.simgr(init_state)
        sim.active[0].regs.rbp = sim.active[0].regs.rsp
        sim.active[0].globals["binsh_addr"] = binsh_addr
        found = None
        i = 0
        while sim.step() and len(sim.active) > 0 and i < 10:
            for st in sim.active:
                if 'sat' in st.globals and st.globals["sat"]:
                    found = st
                    break
            if found != None:
                break
            i += 1
        if found != None:
            valid_constr.append(found.solver.constraints)
            valid_addr.append(cand)

    print("Found OneGadgets:")
    for i in range(len(valid_constr)):
        print("Offset:", hex(valid_addr[i]))
        pconstr = printable_constraints(valid_constr[i])
        print(pconstr)

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help']:
        print("Usage: python angr_one </path/to/libc>")
        exit()
    main(sys.argv[1])
