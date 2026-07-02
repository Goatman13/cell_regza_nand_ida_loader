from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import ida_diskio
import ida_kernwin

def load_file(f, neflags, format):

	idaapi.set_processor_type("ppc", ida_idp.SETPROC_LOADER)
	inf_set_64bit() 
	inf_set_dbg_no_store_path()

	print("[regza_loader] Creating segments")
	add_segm_ex(0x0000000000000000, 0x0000000040000000, 0, 2, 0, 0, 1); # RAM
	add_segm_ex(0x0000000000086BAC, 0x00000000000A2B18, 0, 2, 0, 0, 1); # BEAT RAM (set 0x86BAC - 0xA2B18 RX only, technically it isn't. For compiler it was, so it's safe to do so for code clarity.)	
	add_segm_ex(0x0000000044100000, 0x0000000044100800, 0, 2, 0, 0, 1); # BE7C
	add_segm_ex(0x000000004C000000, 0x000000004C03B000, 0, 2, 0, 0, 1); # LPAR
	add_segm_ex(0x000000004FE00000, 0x000000004FE00800, 0, 2, 0, 0, 1); # PMRC
	add_segm_ex(0x0000002000000000, 0x0000002008000000, 0, 2, 0, 0, 1); # NAND -- FIX ME! ADDR! 
	set_segm_attr(0x0000000000000000, SEGATTR_PERM, SEGPERM_EXEC | SEGPERM_READ | SEGPERM_WRITE)
	set_segm_attr(0x0000000000086BAC, SEGATTR_PERM, SEGPERM_READ)	
	set_segm_attr(0x00000000000A2B20, SEGATTR_PERM, SEGPERM_EXEC | SEGPERM_READ | SEGPERM_WRITE)
	set_segm_attr(0x0000002000000000, SEGATTR_PERM, SEGPERM_EXEC | SEGPERM_READ)	

	add_mapping(0xC000000000000000, 0x20400000, 0x800000) # shadow map kernel, not sure about size.

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
	vaddr = 0x20400000
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

	print("[regza_loader] Set selected TOC")
	#BEAT TOC
	#process_config_line("PPC_TOC=0xA0098");
	#set_name(0xA0098,"TOC",0)

	#KERN TOC	
	process_config_line("PPC_TOC=0x209105C8");
	set_name(0x209105C8,"TOC",0)
	

	sid = add_struc(-1, "OPD_s", 0);
	add_struc_member(sid, "func_ptr", 0x00, idaapi.FF_QWORD | idaapi.FF_0OFF, 0, 8)
	add_struc_member(sid, "toc_ptr", 0x08, idaapi.FF_QWORD | idaapi.FF_0OFF, 0, 8)
	add_struc_member(sid, "env_ptr", 0x10, idaapi.FF_QWORD, 0, 8)

	print("[regza_loader] Create BEAT code")
	addr = 0x9CB90
	end  = 0xA2B18
	while addr < end:
		create_struct(addr, 0x18, "OPD_s")
		idaapi.create_insn(get_qword(addr))
		# Ida ppc module ftl...
		#idaapi.add_func(get_qword(addr), BADADDR)
		addr += 0x18
		
	#print("[regza_loader] Create KERN code")
	#addr = 0x208B8CA8
	#end  = 0x209085C8
	#while addr < end:
	#	create_struct(addr, 0x18, "OPD_s")
	#	print("addr1 = 0x{:X}".format(get_dword(addr+4)))
	#	print("addr2 = 0x{:X}".format(get_dword(addr+4) + 0x20400000))
	#	if get_dword(addr+4) in [0x78D0, 0x78DC, 0x78E8, 0x78F4, 0x7900, 0x27D5C, 0x27D68, 0x27D74, 0x27D80, 0x27D94]: # Ida ppc module ftl...
	#		addr += 0x18
	#		continue
	#	idaapi.create_insn(get_dword(addr+4) + 0x20400000) #204078d0 hang!?
	#	# Ida ppc module ftl...
	#	#idaapi.add_func(get_qword(addr), BADADDR)
	#	addr += 0x18

	print("[regza_loader] Set Vector names")
	set_name(0x0100, "__vector_SystemReset", 0)
	set_name(0x0300, "__vector_DataStorage", 0)
	set_name(0x0380, "__vector_DataSegment", 0)
	set_name(0x0400, "__vector_InstructionStorage", 0)
	set_name(0x0480, "__vector_InstructionSegment", 0)
	set_name(0x0500, "__vector_External", 0)
	set_name(0x0600, "__vector_Alignment", 0)
	set_name(0x0700, "__vector_Program", 0)
	set_name(0x0800, "__vector_FloatingPointUnavailable", 0)
	set_name(0x0900, "__vector_Decrementer", 0)
	set_name(0x0980, "__vector_HypervisorDecrementer", 0)
	set_name(0x0C00, "__vector_SystemCall", 0)
	set_name(0x0D00, "__vector_Trace", 0)
	set_name(0x0F20, "__vector_AltivecUnavailable", 0)
	set_name(0x1200, "__vector_SystemError", 0)
	set_name(0x1600, "__vector_Maintenance", 0)
	set_name(0x1800, "__vector_ThermalManagement", 0)
	# 16FAC syscall_handler
	
	idaapi.create_insn(0x100)
	set_name(0x3200,"start",0)
	ida_kernwin.jumpto(0x100)
	return 1

def accept_file(f, n):
	f.seek(0,2)
	if f.tell() != 0x8400000:
		return 0
	f.seek(0,0)
	if f.read(16).hex().upper() != "D0599B2EFD84181C19D793CE67BC803C":
		return 0
	return "Toshiba CELL Regza NAND Loader"
