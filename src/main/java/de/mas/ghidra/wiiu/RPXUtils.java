package de.mas.ghidra.wiiu;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import de.mas.ghidra.utils.Utils;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RPXUtils {
	private static byte[] RPX_MAGIC = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x02, 0x01, (byte) 0xCA, (byte) 0xFE };
	public static final int SHF_RPL_ZLIB = 0x08000000;
	public static final int SHT_NOBITS = 0x00000008;

	public static final int SHT_RPL_EXPORTS = 0x80000001;
	public static final int SHT_RPL_IMPORTS = 0x80000002;
	public static final int SHT_RPL_CRCS = 0x80000003;
	public static final int SHT_RPL_FILEINFO = 0x80000004;

	public static byte[] convertRPX(ByteProvider bProvider, TaskMonitor monitor)
			throws ElfException, IOException, CancelledException, DataFormatException {
		ElfHeader elfFile = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, bProvider);
		elfFile.parse();

		ByteBuffer buffer = ByteBuffer.allocate(0);

		long shdr_elf_offset = elfFile.e_ehsize() & 0xFFFFFFFF;
		long shdr_data_elf_offset = shdr_elf_offset + elfFile.e_shnum() * elfFile.e_shentsize();

		// Let's get / decompress the section header string table at first.
		ElfSectionHeader sh_str_sh = elfFile.getSections()[elfFile.e_shstrndx()];
		byte[] sh_str_sh_data = new byte[0];
		if (sh_str_sh.getOffset() != 0) {
			if ((sh_str_sh.getFlags() & SHT_NOBITS) != SHT_NOBITS) {
				sh_str_sh_data = sh_str_sh.getData();
				if ((sh_str_sh.getFlags() & SHF_RPL_ZLIB) == SHF_RPL_ZLIB) {
					long section_size_inflated = ByteBuffer.wrap(Arrays.copyOf(sh_str_sh_data, 4)).getInt()
							& 0xFFFFFFFF;
					Inflater inflater = new Inflater();
					inflater.setInput(sh_str_sh_data, 4, (int) sh_str_sh.getSize() - 4); // the first byte is the size

					byte[] decompressed = new byte[(int) section_size_inflated];

					inflater.inflate(decompressed);
					inflater.end();

					sh_str_sh_data = decompressed;
				}
			}
		}

		long curSymbolAddress = 0x01000000;

		for (ElfSectionHeader h : elfFile.getSections()) {
			monitor.checkCanceled();
			long curSize = h.getSize();
			long flags = h.getFlags();
			long offset = h.getOffset();
			String sectionName = Utils.stringFromStringTable(sh_str_sh_data, h.getName());

			if (offset != 0) {
				if ((flags & SHT_NOBITS) != SHT_NOBITS) {
					byte[] data = h.getData();
					if (h.getType() == SHT_RPL_CRCS || h.getType() == SHT_RPL_EXPORTS || h.getType() == SHT_RPL_IMPORTS
							|| h.getType() == SHT_RPL_FILEINFO) {
						data = new byte[0];
						curSize = 0;
					} else {
						if ((flags & SHF_RPL_ZLIB) == SHF_RPL_ZLIB) {
							Utils.logWrapper(
									"Decompressing section " + Utils.stringFromStringTable(sh_str_sh_data, h.getName()),
									monitor);
							long section_size_inflated = ByteBuffer.wrap(Arrays.copyOf(data, 4)).getInt() & 0xFFFFFFFF;
							Inflater inflater = new Inflater();
							inflater.setInput(data, 4, (int) h.getSize() - 4); // the first byte is the size

							byte[] decompressed = new byte[(int) section_size_inflated];

							inflater.inflate(decompressed);

							inflater.end();

							// Is this alignment really necessary?
							curSize = (section_size_inflated + 0x03) & ~0x3;
							flags &= ~SHF_RPL_ZLIB;
							data = decompressed;
						}
					}

					long newEnd = shdr_data_elf_offset + curSize;

					buffer = Utils.checkAndGrowByteBuffer(buffer, newEnd);
					buffer.position((int) shdr_data_elf_offset);
					buffer.put(data);
					offset = shdr_data_elf_offset;
					shdr_data_elf_offset += curSize;
				}
			}

			if (h.getType() == ElfSectionHeaderConstants.SHT_SYMTAB
					|| h.getType() == ElfSectionHeaderConstants.SHT_DYNSYM) {
				Utils.logWrapper("Fix imports for section " + sectionName + " (" + h.getTypeAsString() + ")", monitor);
				int symbolCount = (int) ((int) (curSize) / h.getEntrySize());
				long entryPos = 0;
				for (int i = 0; i < symbolCount; i++) {
					monitor.checkCanceled();
					long entry_offset = (int) (offset + entryPos);

					int sectionIndex = buffer.getShort((int) entry_offset + 14) & 0xFFFF;
					ElfSectionHeader curSection = elfFile.getSections()[sectionIndex];
					int type = curSection.getType();

					if (type == SHT_RPL_IMPORTS) {
						String symbolSectionName = Utils.stringFromStringTable(sh_str_sh_data, curSection.getName());
						buffer.position((int) (entry_offset + 4));
						// Set Value to a custom symbol address
						curSymbolAddress += 4;
						buffer.putInt((int) curSymbolAddress);
						buffer.position((int) (entry_offset + 12));

						// Change type to LOCAL so it won't be in the export list.
						// Force FUNC type so the name will be used in the decompiler.
						byte symbolType = ElfSymbol.STT_FUNC;
						if (symbolSectionName.startsWith(".d")) {
							symbolType = ElfSymbol.STT_OBJECT;
						}

						buffer.put((byte) ((ElfSymbol.STB_LOCAL << 4) | symbolType)); // 12
					}
					entryPos += h.getEntrySize();
				}
			}

			buffer = Utils.checkAndGrowByteBuffer(buffer, shdr_elf_offset + 0x28);

			Utils.logWrapper("Converting section " + sectionName + " (" + h.getTypeAsString() + ")", monitor);

			buffer.position((int) shdr_elf_offset);
			buffer.putInt(h.getName());
			if (h.getType() == SHT_RPL_CRCS || h.getType() == SHT_RPL_FILEINFO) {
				buffer.putInt(ElfSectionHeaderConstants.SHT_NULL);
			} else {
				buffer.putInt(h.getType());
			}
			buffer.putInt((int) flags);

			// Hacky way to fix import relocations
			if (h.getType() == SHT_RPL_IMPORTS) {
				long fixedAddress = 0;
				buffer.putInt((int) fixedAddress);
			} else {
				buffer.putInt((int) h.getAddress());
			}

			buffer.putInt((int) offset);
			buffer.putInt((int) curSize);
			buffer.putInt(h.getLink());
			buffer.putInt(h.getInfo());

			buffer.putInt((int) h.getAddressAlignment());
			buffer.putInt((int) h.getEntrySize());

			shdr_elf_offset += 0x28;
		}

		Utils.logWrapper("Create new ELF header", monitor);

		buffer = Utils.checkAndGrowByteBuffer(buffer, 36);

		buffer.position(0);
		buffer.put(RPX_MAGIC);
		buffer.position(0x10);
		buffer.putShort(ElfConstants.ET_EXEC); // e.e_type());
		buffer.putShort(elfFile.e_machine());
		buffer.putInt(elfFile.e_version());
		buffer.putInt((int) elfFile.e_entry());
		buffer.putInt((int) elfFile.e_phoff());
		buffer.putInt(elfFile.e_ehsize()); // e.e_shoff());
		buffer.putInt(elfFile.e_flags());
		buffer.putShort(elfFile.e_ehsize());
		buffer.putShort(elfFile.e_phentsize());
		buffer.putShort(elfFile.e_phnum());
		buffer.putShort(elfFile.e_shentsize());
		buffer.putShort(elfFile.e_shnum());
		buffer.putShort(elfFile.e_shstrndx());

		return buffer.array();
	}

}