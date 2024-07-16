package main

import "core:bytes"
import "core:io"
import "core:os"
import "core:strings"
import "core:sys/linux"


write_elf_exe :: proc(path: string, text: []u8) -> (err: io.Error) {

	out_buffer := bytes.Buffer{}
	bytes.buffer_grow(&out_buffer, 4 * 1024)

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
