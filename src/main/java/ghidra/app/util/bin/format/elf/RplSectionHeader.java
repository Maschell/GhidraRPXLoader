package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class RplSectionHeader extends ElfSectionHeader {
	public RplSectionHeader(BinaryReader reader, ElfHeader header) throws IOException {
		super(reader, header);
	}
}
