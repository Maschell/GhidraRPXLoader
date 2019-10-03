package cafeloader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.RplSectionHeader;
import ghidra.util.task.TaskMonitor;
import ghidra.util.*;

public class RplConverter {
	public static final int SHF_RPL_ZLIB = 0x08000000;

	public static final int SHT_RPL_EXPORTS = 0x80000001;
	public static final int SHT_RPL_IMPORTS = 0x80000002;
	public static final int SHT_RPL_CRCS = 0x80000003;
	public static final int SHT_RPL_FILEINFO = 0x80000004;

	public static final byte ELFOSABI_CAFE = (byte) 0xCA;
	public static final byte ELFOSABI_VERSION_CAFE = (byte) 0xFE;

	public static byte[] convertRpl(ByteProvider byteProvider, TaskMonitor monitor)
			throws ElfException, IOException, DataFormatException {
		// Read elf header
		RplHeader elfHeader = RplHeader.createRplHeader(RethrowContinuesFactory.INSTANCE, byteProvider);
		BinaryReader reader = elfHeader.getReader();

		// Write elf header
		ByteArrayOutputStream out = new ByteArrayOutputStream((int) byteProvider.length());
		DataConverter dc = BigEndianDataConverter.INSTANCE;
		out.write(ElfConstants.MAGIC_BYTES);
		out.write(ElfConstants.ELF_CLASS_32);
		out.write(ElfConstants.ELF_DATA_BE);
		out.write(ElfConstants.EV_CURRENT);
		out.write(ELFOSABI_CAFE);
		out.write(ELFOSABI_VERSION_CAFE);
		out.write(new byte[7]); // ident padding
		out.write(dc.getBytes(elfHeader.e_type()));
		out.write(dc.getBytes(elfHeader.e_machine()));
		out.write(dc.getBytes(elfHeader.e_version()));
		out.write(dc.getBytes((int) elfHeader.e_entry()));
		out.write(dc.getBytes((int) 0)); // phoff
		out.write(dc.getBytes((int) 0x40)); // shoff
		out.write(dc.getBytes(elfHeader.e_flags()));
		out.write(dc.getBytes(elfHeader.e_ehsize()));
		out.write(dc.getBytes((short) 0)); // phentsize
		out.write(dc.getBytes((short) 0)); // phnum
		out.write(dc.getBytes(elfHeader.e_shentsize()));
		out.write(dc.getBytes(elfHeader.e_shnum()));
		out.write(dc.getBytes(elfHeader.e_shstrndx()));
		out.write(new byte[0x40 - 0x34]); // padding until section headers

		// Read sections
		long sectionDataOffset = elfHeader.e_shoff() + (elfHeader.e_shnum() * elfHeader.e_shentsize());
		ByteArrayOutputStream sectionData = new ByteArrayOutputStream();

		for (int i = 0; i < elfHeader.e_shnum(); ++i) {
			long index = elfHeader.e_shoff() + (i * elfHeader.e_shentsize());
			reader.setPointerIndex(index);
			ElfSectionHeader sectionHeader = RplSectionHeader.createElfSectionHeader((FactoryBundledWithBinaryReader) reader, elfHeader);
			long size = sectionHeader.getSize();
			reader.setPointerIndex(sectionHeader.getOffset());

			// Read & write section data
			if (sectionHeader.getType() != ElfSectionHeaderConstants.SHT_NOBITS) {
				if ((sectionHeader.getFlags() & SHF_RPL_ZLIB) == SHF_RPL_ZLIB) {
					size = reader.readNextInt();
					byte[] inflatedData = new byte[(int) size];
					byte[] deflatedData = reader.readNextByteArray((int) sectionHeader.getSize() - 4);
					Inflater inflater = new Inflater();
					inflater.setInput(deflatedData);
					inflater.inflate(inflatedData);
					inflater.end();
					sectionData.write(inflatedData);
				} else if (size > 0) {
					byte[] inflatedData = reader.readNextByteArray((int) size);
					sectionData.write(inflatedData);
				}
			}

			// Ghidra reads section type as a signed integer which breaks the
			// rpl section types, so we translate them to a different value.
			int sectionType = sectionHeader.getType();
			if (sectionType == SHT_RPL_EXPORTS) {
				sectionType = Cafe_ElfExtension.SHT_RPL_EXPORTS.value;
			} else if (sectionType == SHT_RPL_IMPORTS) {
				sectionType = Cafe_ElfExtension.SHT_RPL_IMPORTS.value;
			} else if (sectionType == SHT_RPL_FILEINFO) {
				sectionType = Cafe_ElfExtension.SHT_RPL_FILEINFO.value;
			} else if (sectionType == SHT_RPL_CRCS) {
				sectionType = Cafe_ElfExtension.SHT_RPL_CRCS.value;
			}

			// Write section header
			out.write(dc.getBytes(sectionHeader.getName()));
			out.write(dc.getBytes(sectionType));
			out.write(dc.getBytes((int) sectionHeader.getFlags()));
			out.write(dc.getBytes((int) sectionHeader.getAddress()));

			if (sectionHeader.getType() != ElfSectionHeaderConstants.SHT_NOBITS && size > 0) {
				out.write(dc.getBytes((int) sectionDataOffset));
				out.write(dc.getBytes((int) size));
				sectionDataOffset += size;
			} else {
				out.write(dc.getBytes((int) sectionHeader.getOffset()));
				out.write(dc.getBytes((int) sectionHeader.getSize()));
			}

			out.write(dc.getBytes(sectionHeader.getLink()));
			out.write(dc.getBytes(sectionHeader.getInfo()));
			out.write(dc.getBytes((int) sectionHeader.getAddressAlignment()));
			out.write(dc.getBytes((int) sectionHeader.getEntrySize()));
		}

		out.write(sectionData.toByteArray());
		return out.toByteArray();
	}
}
