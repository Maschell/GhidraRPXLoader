package cafeloader;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class Cafe_ElfRelocationHandler extends ElfRelocationHandler {
	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf instanceof RplHeader;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		int type = relocation.getType();
		if (type == Cafe_ElfRelocationConstants.R_PPC_NONE) {
			return;
		}

		ElfHeader elf = elfRelocationContext.getElfHeader();
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		int symbolIndex = relocation.getSymbolIndex();
		int addend = (int) relocation.getAddend();
		int offset = (int) relocationAddress.getOffset();
		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		int symbolValue = (int) elfRelocationContext.getSymbolValue(sym);
		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;

		/*
		 * If the symbol is in a SHT_RPL_IMPORTS section then we must add a memory
		 * reference because it will be too far away for the actual relocation to
		 * be valid itself.
		 */
		ElfSectionHeader symbolSection = elf.getSections()[sym.getSectionHeaderIndex()];
		if (symbolSection.getType() == Cafe_ElfExtension.SHT_RPL_IMPORTS.value) {
			String symbolSectionName = symbolSection.getNameAsString();
			if (symbolSectionName.startsWith(".dimport_")) {
				program.getReferenceManager().addMemoryReference(relocationAddress,
					elfRelocationContext.getSymbolAddress(sym), RefType.DATA, SourceType.IMPORTED, 0);
			} else if (symbolSectionName.startsWith(".fimport_")) {
				program.getReferenceManager().addMemoryReference(relocationAddress,
					elfRelocationContext.getSymbolAddress(sym), RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED, 0);
			}

			String rplName = symbolSectionName.split("import_")[1];
			if (!rplName.endsWith(".rpl")) {
				 rplName += ".rpl";
			}

			ExternalLocation location = program.getExternalManager().getUniqueExternalLocation(rplName, sym.getNameAsString());
			if (location != null) {
				try {
					program.getReferenceManager().addExternalReference(relocationAddress, 1,
							  location, SourceType.IMPORTED, RefType.UNCONDITIONAL_CALL);
				} catch (InvalidInputException e) {
					Msg.warn(this, "addExternalReference failed with " + e);
				}
			} else {
				Msg.warn(this, "Failed to find location for " + sym.getNameAsString());
			}
		}

		switch (type) {
			case Cafe_ElfRelocationConstants.R_PPC_ADDR32:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_ADDR16_LO:
				newValue = symbolValue + addend;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_ADDR16_HI:
				newValue = (symbolValue + addend) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_ADDR16_HA:
				newValue = (symbolValue + addend + 0x8000) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_REL24:
				newValue = (symbolValue + addend - offset) >> 2;
				newValue = ((newValue << 2) & Cafe_ElfRelocationConstants.PPC_LOW24);
				newValue = (oldValue & ~Cafe_ElfRelocationConstants.PPC_LOW24) | newValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_REL14:
				newValue = (symbolValue + addend - offset) >> 2;
				newValue = (oldValue & ~Cafe_ElfRelocationConstants.PPC_LOW14) |
					((newValue << 2) & Cafe_ElfRelocationConstants.PPC_LOW14);
				memory.setInt(relocationAddress, newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_GHS_REL16_HA:
				newValue = (symbolValue + addend - offset + 0x8000) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_GHS_REL16_HI:
				newValue = (symbolValue + addend - offset) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_GHS_REL16_LO:
				newValue = (symbolValue + addend - offset);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_DTPREL32:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_DTPMOD32:
				// TODO: Do we need a tlsModuleIndex?
				// *virt_cast<int32_t *>(target) = tlsModuleIndex;
				memory.setInt(relocationAddress, 0);
				break;
			case Cafe_ElfRelocationConstants.R_PPC_EMB_SDA21:
				// TODO: SDA relocations require sda / sda2 base from SHT_RPL_FILEINFO section
			case Cafe_ElfRelocationConstants.R_PPC_EMB_RELSDA:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_SDA21_LO:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_SDA21_HI:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_SDA21_HA:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_RELSDA_LO:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_RELSDA_HI:
			case Cafe_ElfRelocationConstants.R_PPC_DIAB_RELSDA_HA:
			default:
				String symbolName = sym.getNameAsString();
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}
	}
}
