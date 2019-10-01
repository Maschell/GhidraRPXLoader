package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

public class RplSectionHeader extends ElfSectionHeader {
	public static ElfSectionHeader createElfSectionHeader(FactoryBundledWithBinaryReader reader,
			ElfHeader header) throws IOException {
		return ElfSectionHeader.createElfSectionHeader(reader, header);
	}
}
