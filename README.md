## Loongarch64 support for IDA 7.x

Place the `loong64.py` in the `procs` directory.
If you don't see "Loongarch64 (loong64)" in the CPU selection, then check if Python support is working in IDA.

This is written using the public portion of the documentation [here](https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html).

The module has been tested on simple code, but it may contain errors in rarely used instructions. There may be errors in the documentation used to make it. The English documentation is clearly machine translated from Chinese, judging by the nonsense that is written in the description of the instructions.

There is also no support for LVZ/LBT/LSX/LASX extensions that are not described in the documentation. Although they are already supported in `binutils`.

The module also lacks support for stack tracing and combining constants loaded in parts through two instructions.

