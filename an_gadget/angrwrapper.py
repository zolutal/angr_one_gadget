import sys
from typing import List, Tuple
import angr
import logging

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")


class AngrWrapper():
    
    def __init__(self, libc_path: str):
        self.proj: angr.Project = angr.Project(libc_path, auto_load_libs=False, main_opts={'base_addr':0x0})

        self.text_section = self.proj.loader.main_object.sections_map['.text']
        self.binsh_addr: List[int] = list(self.proj.loader.main_object.memory.find(b"/bin/sh"))[0]
        self.execve_addr: int = self.proj.loader.main_object.get_symbol('execve').relative_addr

        self.proj.hook_symbol('execve', self.hook_exec)

    def hook_exec(self, state):
        #TODO find memory access constraint fix
        #rsi_mem = state.memory.load(state.regs.rsi, 8) 
        #rdx_mem = state.memory.load(state.regs.rdx, 8) 
        
        state.solver.add(state.regs.rdi == state.globals["binsh_addr"])
        state.solver.add(state.regs.rsi == 0)#, rsi_mem == 0)
        state.solver.add(state.regs.rdx == 0)#, rdx_mem == 0)

        state.globals["sat"] = state.satisfiable()

    def get_satisfiable_candidates(self, candidate_idxs: List[int], addresses: List[dict]):
        valid_constr = []
        valid_addr = []
        for cand_idx in candidate_idxs:
            cand = addresses[cand_idx]
            init_state = self.proj.factory.blank_state(
                    addr = cand
            )
            sim = self.proj.factory.simgr(init_state)
            sim.active[0].regs.rbp = sim.active[0].regs.rsp
            sim.active[0].globals["binsh_addr"] = self.binsh_addr
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
        return valid_constr, valid_addr

    def printable_constraints(self, constraints):
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
