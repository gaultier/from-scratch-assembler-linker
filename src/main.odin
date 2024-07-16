package main

import "core:bytes"
import "core:fmt"
import "core:io"
import "core:math"
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

write_elf_exe :: proc(path: string, text: []u8) -> (err: io.Error) {

	out_buffer := bytes.Buffer{}
	bytes.buffer_grow(&out_buffer, 4 * 1024)

	// Header

	elf_header_size :: 64
	page_size: u64 = 0x1000
	program_headers := []ElfProgramHeader {
		 {
			type = ElfProgramHeaderTypeLoad,
			p_offset = 0,
			p_vaddr = 0x400000,
			p_paddr = 0x400000,
			flags = ElfProgramHeaderFlagsReadable,
			alignment = page_size,
		},
		 {
			type = ElfProgramHeaderTypeLoad,
			p_offset = page_size,
			p_vaddr = 0x400000 + page_size,
			p_paddr = 0x400000 + page_size,
			p_filesz = cast(u64)(len(text)),
			p_memsz = cast(u64)(len(text)),
			flags = ElfProgramHeaderFlagsExecutable | ElfProgramHeaderFlagsReadable,
			alignment = page_size,
		},
	}
	program_headers_size_unpadded: u64 =
		elf_header_size + cast(u64)len(program_headers) * size_of(ElfProgramHeader)
	program_headers_alignment := cast(u64)math.next_power_of_two(
		cast(int)program_headers_size_unpadded,
	)
	// Backpatch.
	program_headers[0].p_filesz = program_headers_size_unpadded
	program_headers[0].p_memsz = program_headers_size_unpadded

	elf_strings := []string{".shstrtab", ".text"}
	section_headers := []ElfSectionHeader {
		// Null
		{},
		// Code
		 {
			name = 1,
			type = ElfSectionHeaderTypeProgBits,
			addr = 0x401000,
			offset = page_size,
			size = cast(u64)(len(text)),
			align = 1,
		},
		// Strings
		 {
			name = 0,
			type = ElfSectionHeaderTypeStrTab,
			flags = ElfSectionHeaderFlagAlloc | ElfSectionHeaderFlagExecInstr,
			addr = 0,
			offset = page_size + cast(u64)(len(text)),
			size = 0,
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
		bytes.buffer_write(&out_buffer, []u8{0, 0, 0, 0, 0, 0, 0, 0}) or_return
		// Program header table offset.
		bytes.buffer_write(&out_buffer, []u8{0, 0, 0, 0, 0, 0, 0, 0}) or_return
		// Section header table offset.
		bytes.buffer_write(&out_buffer, []u8{0, 0, 0, 0, 0, 0, 0, 0}) or_return


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

	bytes.buffer_write(&out_buffer, text) or_return

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

main :: proc() {
	write_elf_exe(
		"test.bin",
		[]u8{0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x05},
	)
}
