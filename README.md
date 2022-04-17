# What is this?
A python script to find [OneGadgets](https://github.com/david942j/one_gadget) in libc versions using capstone engine to disassemble and using angr to generate constraints.


# Why?
I wanted to play around with angr, this seemed fun, also I don't like having to install ruby for one_gadget and seccomp_tools


# Example
## Usage
```
python angr_one.py </path/to/libc>
```

## Output
```
Found OneGadgets:
Offset: 0xe3b34
 rsi == 0x0,  rdx == 0x0
Offset: 0xe3b31
 r15 == 0x0,  rdx == 0x0
Offset: 0xe3b2e
 r15 == 0x0,  r12 == 0x0
Offset: 0xe3d29
 rsi == 0x0,  rdx == 0x0
Offset: 0xe3d26
 r10 == 0x0,  rdx == 0x0
Offset: 0xe3d23
 r10 == 0x0,  r12 == 0x0
```


# Future Ideas
There is something mentioned in the angr documentation about 'Symbion' which lets you use a gdb state as a starting point for angr's simulation manager. I think it would be really cool to have a gdb or gef plugin that can find satisifiable one_gadgets given the current program state.

Figure out how to make memory constraints work correctly, ([rsi] == NULL and [rdx] == NULL should be valid constraints)

Clean up constraints output to be more readable (partially done, still has many cases with strange outputs though)

Throw it up on PyPi

Add comments to explain the code


# Notes
WIP, will probably continue to mess with some ideas to improve/optimize it further.

Only tested on a few x86_64 libc so far, will try it on some others to confirm it works

It is slower than one_gadget and supports less gadgets at the moment, but it should find all gadgets of one_gadget -l0 (default configuration) as of now.

A tool to find OneGadets using angr exists: [angry_gadget](https://github.com/ChrisTheCoolHut/angry_gadget), it is really slow because it does a CFG analysis on the entirety of libc and the constraints it finds are not usable, I wanted to see if I could make something more practical.