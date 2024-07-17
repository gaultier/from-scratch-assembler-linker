package main

import "core:bytes"
import "core:io"
import "core:mem"
import "core:os"
import "core:strings"
import "core:sys/linux"

ElfProgramHeaderTypeLoad: u32 : 1
ElfProgramHeaderFlagsExecutable: u32 : 1
ElfProgramHeaderFlagsReadable: u32 : 4

ElfProgramHeader :: struct #packed {
	type:      u32,
	flags:     u32,
	p_offset:  u64,
	p_vaddr:   u64,
	p_paddr:   u64,
	p_filesz:  u64,
	p_memsz:   u64,
	alignment: u64,
}
#assert(size_of(ElfProgramHeader) == 56)

ElfSectionHeaderTypeProgBits: u32 : 1
ElfSectionHeaderTypeStrTab: u32 : 3

ElfSectionHeaderFlagAlloc: u64 : 2
ElfSectionHeaderFlagExecInstr: u64 : 4

ElfSectionHeader :: struct #packed {
	name:    u32,
	type:    u32,
	flags:   u64,
	addr:    u64,
	offset:  u64,
	size:    u64,
	link:    u32,
	info:    u32,
	align:   u64,
	entsize: u64,
}
#assert(size_of(ElfSectionHeader) == 64)

write_elf_exe :: proc(path: string, code: []AsmBlock) -> (err: io.Error) {

	code_encoded := []u8{}
	{
		out_code := bytes.Buffer{}
		for block in code {
			for instr in block.instructions {
				encode_asm_instruction(&out_code, instr)
			}
		}

		code_encoded = out_code.buf[:]
	}

	out_buffer := bytes.Buffer{}
	bytes.buffer_grow(&out_buffer, 16 * 1024)

	// Header

	elf_header_size: u64 = 64
	start_vm: u64 = 1 << 22
	page_size: u64 = 0x1000
	program_headers := []ElfProgramHeader {
		 {
			type = ElfProgramHeaderTypeLoad,
			p_offset = 0,
			p_vaddr = start_vm,
			p_paddr = start_vm,
			flags = ElfProgramHeaderFlagsReadable,
			alignment = page_size,
		},
		 {
			type = ElfProgramHeaderTypeLoad,
			p_offset = page_size,
			p_vaddr = start_vm + page_size,
			p_paddr = start_vm + page_size,
			p_filesz = cast(u64)(len(code_encoded)),
			p_memsz = cast(u64)(len(code_encoded)),
			flags = ElfProgramHeaderFlagsExecutable | ElfProgramHeaderFlagsReadable,
			alignment = page_size,
		},
	}
	program_headers_size_unpadded: u64 =
		elf_header_size + cast(u64)len(program_headers) * size_of(ElfProgramHeader)
	// Backpatch.
	program_headers[0].p_filesz = program_headers_size_unpadded
	program_headers[0].p_memsz = program_headers_size_unpadded

	elf_strings := []string{".shstrtab", ".text"}
	strings_size: u64 = 1
	for s in elf_strings {
		strings_size += cast(u64)len(s) + 1 // Null terminator.
	}
	section_headers := []ElfSectionHeader {
		// Null
		{},
		// Code
		 {
			name = 11,
			type = ElfSectionHeaderTypeProgBits,
			flags = ElfSectionHeaderFlagExecInstr | ElfSectionHeaderFlagAlloc,
			addr = start_vm + page_size,
			offset = page_size,
			size = cast(u64)(len(code_encoded)),
			align = 1,
		},
		// Strings
		 {
			name = 1,
			type = ElfSectionHeaderTypeStrTab,
			flags = 0,
			addr = 0,
			offset = page_size + cast(u64)(len(code_encoded)),
			size = strings_size,
			align = 1,
		},
	}

	{
		ELF_MAGIC: []u8 : {0x7f, 'E', 'L', 'F'}
		bytes.buffer_write(&out_buffer, ELF_MAGIC) or_return

		bytes.buffer_write_byte(&out_buffer, 2) or_return // 64 bit.
		bytes.buffer_write_byte(&out_buffer, 1) or_return // Little-endian.
		bytes.buffer_write_byte(&out_buffer, 1) or_return // ELF header version = 1.
		bytes.buffer_write_byte(&out_buffer, 0) or_return // OS ABI, 0 = System V.
		bytes.buffer_write(&out_buffer, []u8{0, 0, 0, 0, 0, 0, 0, 0}) or_return // Padding.
		bytes.buffer_write(&out_buffer, []u8{2, 0}) or_return // Type: Executable.
		bytes.buffer_write(&out_buffer, []u8{0x3e, 0}) or_return // ISA x86_64.
		bytes.buffer_write(&out_buffer, []u8{0x1, 0, 0, 0}) or_return // ELF version = 1.
		assert(len(out_buffer.buf) == 24)

		// Program entry offset.
		program_entry_offset: u64 = program_headers[1].p_vaddr
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&program_entry_offset)) or_return
		// Program header table offset.
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&elf_header_size)) or_return
		// Section header table offset.
		section_header_table_offset: u64 = page_size + cast(u64)len(code_encoded) + strings_size
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&section_header_table_offset)) or_return


		bytes.buffer_write(&out_buffer, []u8{0, 0, 0, 0}) or_return // Flags.
		assert(len(out_buffer.buf) == 52)

		bytes.buffer_write(&out_buffer, []u8{64, 0}) or_return // ELF header size.
		bytes.buffer_write(&out_buffer, []u8{size_of(ElfProgramHeader), 0}) or_return // Size of an entry in the program header table.
		program_headers_len := cast(u16)(len(program_headers))
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&program_headers_len)) or_return // Number of entries in the program header table.
		section_headers_entry_size := cast(u16)size_of(ElfSectionHeader)
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&section_headers_entry_size)) or_return // Size of an entry in the section header table.
		section_headers_len := cast(u16)len(section_headers)
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&section_headers_len)) or_return // Number of entries in the section header table.

		section_header_string_table_index: u16 = 2
		bytes.buffer_write(
			&out_buffer,
			mem.ptr_to_bytes(&section_header_string_table_index),
		) or_return // Section index in the section header table.

		assert(len(out_buffer.buf) == 64)
	}
	for &ph in program_headers {
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&ph)) or_return
	}

	for _ in len(out_buffer.buf) ..< cast(int)page_size {
		bytes.buffer_write_byte(&out_buffer, 0) or_return // Pad.
	}

	bytes.buffer_write(&out_buffer, code_encoded) or_return

	bytes.buffer_write_byte(&out_buffer, 0) or_return // Null string.
	for s in elf_strings {
		bytes.buffer_write(&out_buffer, transmute([]u8)s) or_return
		bytes.buffer_write_byte(&out_buffer, 0) or_return // Null terminator.
	}

	for &sh in section_headers {
		bytes.buffer_write(&out_buffer, mem.ptr_to_bytes(&sh)) or_return
	}


	file, err_open := os.open(path, os.O_WRONLY | os.O_CREATE)
	assert(err_open == {})
	defer os.close(file)

	n_written, err_write := os.write(file, out_buffer.buf[:])
	assert(err_write == {})
	assert(n_written == len(out_buffer.buf))

	path_c := strings.clone_to_cstring(path, context.temp_allocator)
	assert(
		linux.chmod(
			path_c,
			linux.Mode{linux.Mode_Bits.IXUSR, linux.Mode_Bits.IWUSR, linux.Mode_Bits.IRUSR},
		) ==
		{},
	)

	return {}
}

AsmRegister :: enum {
	Eax,
	Edi,
	Edx,
	Rsi,
	Rsp,
	// Etc.
}

AsmImmediate :: union {
	u8,
	u16,
	u32,
	u64,
}

AsmDisplacement :: struct {}

AsmEffectiveAddress :: struct {
	base:  AsmRegister,
	index: u8,
	scale: u8,
}

AsmOperand :: union {
	AsmRegister,
	AsmImmediate,
	AsmEffectiveAddress,
}

AsmSyscall :: struct {}

AsmMov :: struct {
	op1: AsmOperand,
	op2: AsmOperand,
}

AsmInc :: struct {
	op: AsmRegister,
}

AsmPush :: struct {
	op: AsmOperand,
}

AsmLea :: struct {
	op1: AsmRegister,
	op2: AsmEffectiveAddress,
}

AsmSub :: struct {
	op1: AsmRegister,
	op2: AsmOperand,
}

AsmAdd :: struct {
	op1: AsmRegister,
	op2: AsmOperand,
}


AsmInstruction :: union {
	AsmSyscall,
	AsmMov,
	AsmInc,
	AsmPush,
	AsmLea,
	AsmSub,
	AsmAdd,
}

AsmBlockFlags :: enum {
	Global,
}

AsmBlock :: struct {
	name:         string,
	flags:        AsmBlockFlags,
	instructions: []AsmInstruction,
}

asm_encode_sib :: proc(address: AsmEffectiveAddress) -> u8 {
	assert(address.scale <= 0b11)
	assert(address.index <= 0b111)

	return address.scale << 6 | address.index << 3 | asm_register_numeric_value(address.base)
}

asm_register_size :: proc(reg: AsmRegister) -> u8 {
	switch reg {
	case .Eax:
		return 32
	case .Edi:
		return 32
	case .Edx:
		return 32
	case .Rsp:
		return 64
	case .Rsi:
		return 64
	}
	return 0
}

asm_register_is_extended :: proc(reg: AsmRegister) -> bool {
	// FIXME
	return false
}

asm_register_numeric_value :: proc(reg: AsmRegister) -> u8 {
	switch reg {
	case .Eax:
		return 0
	case .Edx:
		return 2
	case .Edi:
		return 7
	case .Rsp:
		return 4
	case .Rsi:
		return 6
	}
	return 0
}

asm_register_and_opcode_to_modrm :: proc(reg: AsmRegister, opcode: u8) -> u8 {
	// Plain register, no displacement.
	mask: u8 = 0b11_00_0000

	switch opcode {
	case 5:
		return mask | 0xe8 | asm_register_numeric_value(reg)
	case 0:
		return mask | 0xc0 | asm_register_numeric_value(reg)
	case:
		assert(false, "unimplemented")
	}
	return 0
}

encode_asm_instruction :: proc(out: ^bytes.Buffer, instr: AsmInstruction) {
	switch v in instr {
	case AsmSyscall:
		bytes.buffer_write(out, []u8{0x0f, 0x05})
	case AsmMov:
		op1_reg, is_op1_reg := v.op1.(AsmRegister)
		op1_effective_addr, is_op1_effective_addr := v.op1.(AsmEffectiveAddress)
		assert(is_op1_reg || is_op1_effective_addr, "unimplemented")
		op2, is_op2_immediate := v.op2.(AsmImmediate)
		assert(is_op2_immediate, "unimplemented")

		#partial switch y in op2 {
		case u32:
			bytes.buffer_write_byte(out, 0xb8 + asm_register_numeric_value(op1_reg))
			value := y
			bytes.buffer_write(out, mem.ptr_to_bytes(&value))
		case u8:
			assert(is_op1_effective_addr, "unimplemented")

			bytes.buffer_write_byte(out, 0xc6)

			modrm_mask_displacement_u8: u8 = 0b01_00_0000
			modrm := modrm_mask_displacement_u8
			#partial switch op1_effective_addr.base {
			case .Rsp:
				modrm |= asm_register_numeric_value(op1_effective_addr.base)
				bytes.buffer_write_byte(out, modrm)

				base_mask_sp: u8 = 0b100_000
				index_mask_sp: u8 = 0b100
				bytes.buffer_write_byte(out, base_mask_sp | index_mask_sp)
				bytes.buffer_write_byte(out, op1_effective_addr.index)

			case:
				assert(false, "unimplemented")
			}

			bytes.buffer_write_byte(out, y)

		case:
			assert(false, "unimplemented")
		}
	case AsmInc:
		modrm: u8 = 0b1100_0000
		reg_size := asm_register_size(v.op)
		assert(reg_size == 32, "unimplemented")
		bytes.buffer_write(out, []u8{0xff, modrm + asm_register_numeric_value(v.op)})

	case AsmPush:
		op, is_op_immediate := v.op.(AsmImmediate)
		assert(is_op_immediate, "unimplemented")

		op_u8, is_u8 := op.(u8)
		assert(is_u8, "unimplemented")

		bytes.buffer_write(out, []u8{0x6a, op_u8})

	case AsmLea:
		mask_64_bits_mode: u8 = 0b1000
		rex: u8 = 0b0100_0000 | mask_64_bits_mode
		modrm1: u8 = asm_register_numeric_value(v.op1) << 3 | 0b100


		op2_reg := v.op2.base
		assert(v.op2.index == 0, "unimplemented")
		assert(v.op2.scale == 0, "unimplemented")

		modrm2: u8 = asm_register_numeric_value(op2_reg) << 3 | 0b100

		bytes.buffer_write(out, []u8{rex, 0x8d, modrm1, modrm2})

	case AsmSub:
		op2, is_immediate := v.op2.(AsmImmediate)
		assert(is_immediate, "unimplemented")

		if asm_register_size(v.op1) == 64 {
			rex: u8 = 0b0100_1000
			bytes.buffer_write_byte(out, rex)
		}

		#partial switch y in op2 {
		case u8:
			opcode: u8 = 5
			modrm := asm_register_and_opcode_to_modrm(v.op1, opcode)
			bytes.buffer_write(out, []u8{0x83, modrm, y})
		case:
			assert(false, "unimplemented")
		}

	case AsmAdd:
		op2, is_immediate := v.op2.(AsmImmediate)
		assert(is_immediate, "unimplemented")

		if asm_register_size(v.op1) == 64 {
			rex: u8 = 0b0100_1000
			bytes.buffer_write_byte(out, rex)
		}

		#partial switch y in op2 {
		case u8:
			opcode: u8 = 0
			modrm := asm_register_and_opcode_to_modrm(v.op1, opcode)
			bytes.buffer_write(out, []u8{0x83, modrm, y})
		case:
			assert(false, "unimplemented")
		}
	}


}

main :: proc() {
	syscall_linux_exit: u32 = 60
	exit_code: u32 = 2

	syscall_linux_write: u32 = 1
	stdout: u32 = 1
	msg_len: u32 = 5

	code := []AsmBlock {
		 {
			name = "_start",
			flags = .Global,
			instructions = []AsmInstruction {
				AsmSub{op1 = .Rsp, op2 = AsmImmediate(u8(5))},
				AsmMov {
					op1 = AsmEffectiveAddress{base = .Rsp, index = 0},
					op2 = AsmImmediate(u8('h')),
				},
				AsmMov {
					op1 = AsmEffectiveAddress{base = .Rsp, index = 1},
					op2 = AsmImmediate(u8('e')),
				},
				AsmMov {
					op1 = AsmEffectiveAddress{base = .Rsp, index = 2},
					op2 = AsmImmediate(u8('l')),
				},
				AsmMov {
					op1 = AsmEffectiveAddress{base = .Rsp, index = 3},
					op2 = AsmImmediate(u8('l')),
				},
				AsmMov {
					op1 = AsmEffectiveAddress{base = .Rsp, index = 4},
					op2 = AsmImmediate(u8('o')),
				},
				AsmMov{op1 = AsmRegister(.Eax), op2 = AsmImmediate(syscall_linux_write)},
				AsmMov{op1 = AsmRegister(.Edi), op2 = AsmImmediate(stdout)},
				AsmLea{op1 = .Rsi, op2 = AsmEffectiveAddress{base = .Rsp}},
				AsmMov{op1 = AsmRegister(.Edx), op2 = AsmImmediate(msg_len)},
				AsmSyscall{},
				AsmAdd{op1 = .Rsp, op2 = AsmImmediate(u8(5))},
				AsmMov{op1 = AsmRegister(.Eax), op2 = AsmImmediate(syscall_linux_exit - 1)},
				AsmInc{op = .Eax},
				AsmMov{op1 = AsmRegister(.Edi), op2 = AsmImmediate(exit_code)},
				AsmSyscall{},
			},
		},
	}

	write_elf_exe("test.bin", code)
}
