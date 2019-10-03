package cafeloader;

import java.io.IOException;
import java.math.BigInteger;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class Cafe_ElfExtension extends ElfExtension {
	/*
	 * Note that these values are not the REAL CafeOS section header types, we
	 * transform them to this in the RpxConversion stage because ElfSectionHeaderType
	 * expects an int > 0 and unfortunately the real CafeOS SHT values are invalid for this.
	 */
	public static final ElfSectionHeaderType SHT_RPL_EXPORTS = new ElfSectionHeaderType(0x0CAFE001,
		"SHT_RPL_EXPORTS", "Section contains RPL exports");
	public static final ElfSectionHeaderType SHT_RPL_IMPORTS = new ElfSectionHeaderType(0x0CAFE002,
		"SHT_RPL_IMPORTS", "Section contains RPL imports");
	public static final ElfSectionHeaderType SHT_RPL_CRCS = new ElfSectionHeaderType(0x0CAFE003,
		"SHT_RPL_CRCS", "Section contains RPL crcs");
	public static final ElfSectionHeaderType SHT_RPL_FILEINFO = new ElfSectionHeaderType(0x0CAFE004,
		"SHT_RPL_FILEINFO", "Section contains RPL file info");

	public static final int RPL_FILEINFO_V3 = 0xCAFE0300;
	public static final int RPL_FILEINFO_V4_1 = 0xCAFE0401;
	public static final int RPL_FILEINFO_V4_2 = 0xCAFE0402;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf instanceof RplHeader;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_PPC";
	}

	/*
	 * Process elf symbols which are in SHT_RPL_IMPORTS sections to be external imports.
	 */
	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal)  {
		ElfHeader elf = elfLoadHelper.getElfHeader();
		ElfSectionHeader section = elf.getSections()[elfSymbol.getSectionHeaderIndex()];

		if (section.getType() != SHT_RPL_IMPORTS.value) {
			return address;
		}

		String name = elfSymbol.getNameAsString();
		if (name == null) {
			return address;
		}

		if (!elfSymbol.isFunction() && !elfSymbol.isObject()) {
			return address;
		}

		String sectionName = section.getNameAsString();
		if (!sectionName.startsWith(".fimport_") && !sectionName.startsWith(".dimport_")) {
			return address;
		}

		String rplName = sectionName.split("import_")[1];
		if (!rplName.endsWith(".rpl")) {
			rplName += ".rpl";
		}

		try {
			Program program = elfLoadHelper.getProgram();
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			elfLoadHelper.createSymbol(address, name, true, elfSymbol.isAbsolute(), null);

			if (elfSymbol.isFunction()) {
				program.getExternalManager().addExtFunction(rplName, name, address,
						SourceType.IMPORTED);
			} else if (elfSymbol.isObject()) {
				program.getExternalManager().addExtLocation(rplName, name, address,
						SourceType.IMPORTED);
			}

			return null;
		} catch (InvalidInputException e) {
		} catch (DuplicateNameException e) {
		}

		return address;
	}

	@Override
	public Boolean isSectionWritable(ElfSectionHeader section) {
		// For some reason .rpl files have .rodata marked with W flag,
		// forcing it to read only will help improve decompiler output.
		String name = section.getNameAsString();
		if (name != null && name.contentEquals(".rodata")) {
			return false;
		}

		// Force .dimport section to writeable so compiler does not inline
		// the value... even though its external...
		// TODO: Maybe there is a better way to define .dimport/.fimport
		// sections as not real loaded in memory sections so that the
		// compiler does not inline it's values?
		if (name != null && name.startsWith(".dimport")) {
			return true;
		}

		return (section.getFlags() & ElfSectionHeaderConstants.SHF_WRITE) != 0;
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		ElfHeader elf = elfLoadHelper.getElfHeader();
		for (ElfSectionHeader sectionHeader : elf.getSections()) {
			int headertype = sectionHeader.getType();
			if (headertype == SHT_RPL_CRCS.value) {
				processRplCrcs(elfLoadHelper, sectionHeader);
			} else if (headertype == SHT_RPL_FILEINFO.value) {
				processRplFileInfo(elfLoadHelper, sectionHeader);
			} else if (headertype == SHT_RPL_IMPORTS.value) {
				processRplImports(elfLoadHelper, sectionHeader);
			} else if (headertype == SHT_RPL_EXPORTS.value) {
				processRplExports(elfLoadHelper, sectionHeader);
			}
		}
	}

	private void processRplImports(ElfLoadHelper elfLoadHelper, ElfSectionHeader sectionHeader) {
		// Clear the section data otherwise analysis will identify strings in it.
		Address sectionAddress = elfLoadHelper.findLoadAddress(sectionHeader, 0);
		int sectionSize = (int) sectionHeader.getSize();
		elfLoadHelper.createUndefinedData(sectionAddress, sectionSize);

		byte[] zeroes = new byte[sectionSize];
		try {
			elfLoadHelper.getProgram().getMemory().setBytes(sectionAddress, zeroes);
		} catch (MemoryAccessException e) {
		}
	}

	private void processRplExports(ElfLoadHelper elfLoadHelper, ElfSectionHeader sectionHeader) {
		String sectionName = sectionHeader.getNameAsString();
		if (sectionName.contentEquals(".dexports")) {
			// Create symbols for data exports
			BinaryReader reader = elfLoadHelper.getElfHeader().getReader();
			reader.setPointerIndex(sectionHeader.getOffset());

			try {
				int count = reader.readNextInt();
				/* int signature = */ reader.readNextInt();
				for (int i = 0; i < count; ++i) {
					int value = reader.readNextInt();
					int nameOffset = reader.readNextInt();
					/* boolean isTlsExport = (nameOffset & 0x80000000) != 0; */
					String name = reader.readAsciiString(sectionHeader.getOffset() + (nameOffset & 0x7FFFFFFF));
					elfLoadHelper.createSymbol(elfLoadHelper.getDefaultAddress(value), name, true, false, null);
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InvalidInputException e) {
				e.printStackTrace();
			}
		}

		// Clear the section data otherwise analysis will identify strings in it.
		Address sectionAddress = elfLoadHelper.findLoadAddress(sectionHeader, 0);
		int sectionSize = (int) sectionHeader.getSize();
		elfLoadHelper.createUndefinedData(sectionAddress, sectionSize);

		byte[] zeroes = new byte[sectionSize];
		try {
			elfLoadHelper.getProgram().getMemory().setBytes(sectionAddress, zeroes);
		} catch (MemoryAccessException e) {
		}
	}

	private void processRplCrcs(ElfLoadHelper elfLoadHelper, ElfSectionHeader sectionHeader) {
		Address address = elfLoadHelper.findLoadAddress(sectionHeader, 0);
		if (address == null) {
			return;
		}

		try {
			for (long i = 0; i < sectionHeader.getSize(); i += 4) {
				elfLoadHelper.createData(address.add(i), DWordDataType.dataType);
			}
		} catch (AddressOutOfBoundsException e) {
		}
	}

	private void processRplFileInfo(ElfLoadHelper elfLoadHelper, ElfSectionHeader sectionHeader) {
		Address fileInfoAddr = elfLoadHelper.findLoadAddress(sectionHeader, 0);
		if (fileInfoAddr == null) {
			return;
		}

		int version = RPL_FILEINFO_V3;
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		try {
			version = memory.getInt(fileInfoAddr);
		} catch (MemoryAccessException e) {
			Msg.warn(this, "Failed to read RplFileInfo version");
		}

		Structure fileInfo =
			new StructureDataType(new CategoryPath("/ELF"), "Elf32_RplFileInfo", 0);

		int filenameOffset = 0;
		int sdaBase = 0;
		int sda2Base = 0;
		if (version >= RPL_FILEINFO_V3) {
			fileInfo.add(DWordDataType.dataType, "version", null);
			fileInfo.add(DWordDataType.dataType, "textSize", null);
			fileInfo.add(DWordDataType.dataType, "textAlign", null);
			fileInfo.add(DWordDataType.dataType, "dataSize", null);
			fileInfo.add(DWordDataType.dataType, "dataAlign", null);
			fileInfo.add(DWordDataType.dataType, "loadSize", null);
			fileInfo.add(DWordDataType.dataType, "loadAlign", null);
			fileInfo.add(DWordDataType.dataType, "tempSize", null);
			fileInfo.add(DWordDataType.dataType, "trampAdjust", null);
			fileInfo.add(DWordDataType.dataType, "sdaBase", null);
			fileInfo.add(DWordDataType.dataType, "sda2Base", null);
			fileInfo.add(DWordDataType.dataType, "stackSize", null);
			fileInfo.add(DWordDataType.dataType, "filenameOffset", null);

			try {
				sdaBase = memory.getInt(fileInfoAddr.add(0x24));
				sda2Base = memory.getInt(fileInfoAddr.add(0x28));
				filenameOffset = memory.getInt(fileInfoAddr.add(0x30));
			} catch (MemoryAccessException e) {
				Msg.warn(this, "Failed to read filenameOffset");
			}
		}

		Address minAddress = program.getAddressFactory().getDefaultAddressSpace().getMinAddress();
		Address maxAddress = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress();
		if (sdaBase != 0 && minAddress != null && maxAddress != null) {
			Register r13 = elfLoadHelper.getProgram().getRegister("r13");
			try {
				program.getProgramContext().setValue(r13, minAddress, maxAddress, BigInteger.valueOf(sdaBase));
			} catch (ContextChangeException e) {
				Msg.warn(this, "Error setting r13 to sdabase: " + e);
			}
		}

		if (sda2Base != 0 && minAddress != null && maxAddress != null) {
			Register r2 = elfLoadHelper.getProgram().getRegister("r2");
			try {
				program.getProgramContext().setValue(r2, minAddress, maxAddress, BigInteger.valueOf(sda2Base));
			} catch (ContextChangeException e) {
				Msg.warn(this, "Error setting r2 to sda2base: " + e);
			}
		}

		int tagOffset = 0;
		if (version >= RPL_FILEINFO_V4_1) {
			fileInfo.add(DWordDataType.dataType, "flags", null);
			fileInfo.add(DWordDataType.dataType, "heapSize", null);
			fileInfo.add(DWordDataType.dataType, "tagOffset", null);

			try {
				tagOffset = memory.getInt(fileInfoAddr.add(0x3C));
			} catch (MemoryAccessException e) {
				Msg.warn(this, "Failed to read tagOffset");
			}
		}

		if (version >= RPL_FILEINFO_V4_2) {
			fileInfo.add(DWordDataType.dataType, "minVersion", null);
			fileInfo.add(DWordDataType.dataType, "compressionLevel", null);
			fileInfo.add(DWordDataType.dataType, "trampAddition", null);
			fileInfo.add(DWordDataType.dataType, "fileInfoPad", null);
			fileInfo.add(DWordDataType.dataType, "cafeSdkVersion", null);
			fileInfo.add(DWordDataType.dataType, "cafeSdkRevision", null);
			fileInfo.add(WordDataType.dataType, "tlsModuleIndex", null);
			fileInfo.add(WordDataType.dataType, "tlsAlignShift", null);
			fileInfo.add(DWordDataType.dataType, "runtimeFileInfoSize", null);
		}
		elfLoadHelper.createData(fileInfoAddr, fileInfo);

		// Mark filename as a string
		if (filenameOffset != 0) {
			try {
				elfLoadHelper.createData(fileInfoAddr.add(filenameOffset), TerminatedStringDataType.dataType);
			} catch (AddressOutOfBoundsException e) {
			}
		}

		// Mark tags as strings
		if (tagOffset != 0) {
			try {
				Address tagAddress = fileInfoAddr.add(tagOffset);
				while (true) {
					Data d = elfLoadHelper.createData(tagAddress, TerminatedStringDataType.dataType);
					int length = d.getLength();
					if (length == 0) {
						break;
					}
					tagAddress = tagAddress.add(length);
				}
			} catch (AddressOutOfBoundsException e) {
			}
		}
	}
}
