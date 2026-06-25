from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import ida_diskio

def load_file(f, neflags, format):

	idaapi.set_processor_type("ppc", ida_idp.SETPROC_LOADER)
	inf_set_64bit() 
	inf_set_dbg_no_store_path()

	print("[regza_loader] Creating segments")
	add_segm_ex(0x0000000000000000, 0x0000000040000000, 0, 2, 0, 0, 1); # RAM
	add_segm_ex(0x0000000044100000, 0x0000000044100800, 0, 2, 0, 0, 1); # BE7C
	add_segm_ex(0x000000004C000000, 0x000000004C03B000, 0, 2, 0, 0, 1); # LPAR
	add_segm_ex(0x000000004FE00000, 0x000000004FE00800, 0, 2, 0, 0, 1); # PMRC
	add_segm_ex(0x0000002000000000, 0x0000002008000000, 0, 2, 0, 0, 1); # NAND -- FIX ME! ADDR! 
	set_segm_attr(0x0000000000000000, SEGATTR_PERM, SEGPERM_EXEC | SEGPERM_READ | SEGPERM_WRITE)
	set_segm_attr(0x0000002000000000, SEGATTR_PERM, SEGPERM_EXEC | SEGPERM_READ)	

	print("[regza_loader] TODO! Initializing RAM segment")


	print("[regza_loader] Loading NAND segment into database")
	paddr = 0
	vaddr = 0
	while(paddr < 0x8400000):
		f.file2base(paddr, 0x0000002000000000 + vaddr, 0x0000002000000800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
	
	print("[regza_loader] Loading BEAT segment into database")
	requested_size = 0xB9B88
	paddr = 0x8400
	vaddr = 0
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800
	
	print("[regza_loader] Loading KERN segment into database")
	requested_size = 0x52CB10
	paddr = 0xCE400
	vaddr = 0x52CB10
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800
	
	print("[regza_loader] Loading ROOT segment into database")
	requested_size = 0x2C5E000
	paddr = 0x627C00
	vaddr = 0x1B300000
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800
	
	print("[regza_loader] Loading BE7C segment into database")
	requested_size = 0x139
	paddr = 0x33EAC00
	vaddr = 0x44100000
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800
	
	print("[regza_loader] Loading LPAR segment into database")
	requested_size = 0x3A80A
	paddr = 0x33F3000
	vaddr = 0x4C000000
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800
	
	print("[regza_loader] Loading PMRC segment into database")
	requested_size = 0xE5
	paddr = 0x3435000
	vaddr = 0x4FE00000
	size  = 0
	while(size < requested_size):
		f.file2base(paddr, vaddr, 0x800 + vaddr, 0)
		vaddr += 0x800 # 0x800 chunk.
		paddr += 0x840 # 0x800 chunk + 0x40 ecc or whatever.
		size  += 0x800

	#process_config_line("PPC_TOC=0x123456");
	#set_name(0x123456,"TOC",0)

	idaapi.create_insn(0x100)
	set_name(0x3200,"start",0)
	return 1

def accept_file(f, n):
	f.seek(0,2)
	if f.tell() != 0x8400000:
		return 0
	f.seek(0,0)
	if f.read(16).hex().upper() != "D0599B2EFD84181C19D793CE67BC803C":
		return 0
	return "Toshiba CELL Regza NAND Loader"
