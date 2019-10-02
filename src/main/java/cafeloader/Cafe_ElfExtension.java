package cafeloader;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
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
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		ElfHeader elf = elfLoadHelper.getElfHeader();
		for (ElfSectionHeader sectionHeader : elf.getSections()) {
			int headertype = sectionHeader.getType();
			if (headertype == SHT_RPL_CRCS.value) {
				processRplCrcs(elfLoadHelper, sectionHeader);
			} else if (headertype == SHT_RPL_FILEINFO.value) {
				processRplFileInfo(elfLoadHelper, sectionHeader);
			}
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
		Memory memory = elfLoadHelper.getProgram().getMemory();
		try {
			version = memory.getInt(fileInfoAddr);
		} catch (MemoryAccessException e) {
			Msg.warn(this, "Failed to read RplFileInfo version");
		}

		Structure fileInfo =
			new StructureDataType(new CategoryPath("/ELF"), "Elf32_RplFileInfo", 0);

		int filenameOffset = 0;
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
				filenameOffset = memory.getInt(fileInfoAddr.add(0x30));
			} catch (MemoryAccessException e) {
				Msg.warn(this, "Failed to read filenameOffset");
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
