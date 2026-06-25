# Toshiba Cell Regza NAND Dump Loader
IDA Loader for Toshiba CELL Regza NAND Dump. Map basics in ram, NAND itself is mapped at 0x2000000000 which is wrong and should be somewhere in SB space.
Loaded NAND is cleared from ECC.

RAM loaded stuff is: BEAT, KERN, ROOT additionally mapped: BE7C, LPAR, PRMC.
Todo: init ram, add vectors, maybe more.
