package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.zip.DataFormatException;

import de.mas.ghidra.wiiu.RPXUtils;
import generic.continues.GenericFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class RPXLoader extends ElfLoader {
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		byte[] header = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x02, 0x01, (byte) 0xCA, (byte) 0xFE };
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (Arrays.equals(provider.readBytes(0, header.length), header)) {
			List<QueryResult> results = QueryOpinionService.query(getName(), "0", null);

			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
			return loadSpecs;

		}
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "Wii U Executable (RPX/RPL)";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	// public static final int R_PPC_REL24 = 10;

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws IOException {

		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);

			byte[] data = RPXUtils.convertRPX(provider, monitor);

			ElfHeader elf = ElfHeader.createElfHeader(factory, new ByteArrayProvider(data));

			ElfProgramBuilder.loadElf(elf, program, options, log, handler, monitor);

			AddressSpace aspace = program.getAddressFactory().getDefaultAddressSpace();

			for (ElfRelocationTable table : elf.getRelocationTables()) {
				for (ElfRelocation reloc : table.getRelocations()) {
					int sindex = reloc.getSymbolIndex();

					ElfSymbol symbol = table.getAssociatedSymbolTable().getSymbols()[sindex];
					ElfSectionHeader section = elf.getSections()[symbol.getSectionHeaderIndex()];
					if (section.getType() == RPXUtils.SHT_RPL_IMPORTS) {
						int offset = (int) (reloc.getOffset() & ~3);

						String rplName = section.getNameAsString();
						if (rplName.contains("import_")) {
							rplName = rplName.split("import_")[1];
							if (!rplName.endsWith(".rpl")) {
								rplName += ".rpl";
							}
						} else {
							continue;
						}

						Address addr = aspace.getAddress(offset);
						boolean isData = section.getNameAsString().startsWith(".d");

						ExternalManagerDB em = (ExternalManagerDB) program.getExternalManager();
						ExternalLocation location;
						RefType type = RefType.UNCONDITIONAL_CALL;
						if (!isData) {
							location = em.addExtFunction(rplName, symbol.getNameAsString(), null, SourceType.IMPORTED);
						} else {
							type = RefType.DATA;
							location = em.addExtLocation(rplName, symbol.getNameAsString(), null, SourceType.IMPORTED);
						}

						// Attempt to remove to auto analyzed memory reference that's created due to the
						// relocation.
						// if (reloc.getType() == R_PPC_REL24) {
						// Relocation r = program.getRelocationTable().getRelocation(addr);
						// program.getRelocationTable().remove(r);
						// }

						// We need this to have working references. (=> clicking on Imports, Show
						// Referenences to.. is working)
						// Setting the RefType.INVALID works for some reason!
						// If the set it to DATA, everything is treated like DATA, and if we use
						// something like "UNCONDITIONAL_CALL" for functions
						// then decompiler doesn't get the right function names anymore.

						program.getReferenceManager().addExternalReference(addr, 1, location, SourceType.IMPORTED,
								RefType.INVALID);
						// force the memory reference to the target address, even if the referenced
						// address is too far away!
						program.getReferenceManager().addMemoryReference(addr, aspace.getAddress(symbol.getValue()),
								type, SourceType.IMPORTED, 0);

						// Add a comment to easily see from which rpl the function is coming.
						program.getListing().setComment(addr, 0, rplName + "::" + symbol.getNameAsString());
					}
				}
			}

		} catch (ElfException e) {
			throw new IOException(e.getMessage());
		} catch (CancelledException e) {
			// TODO: Caller should properly handle CancelledException instead
			throw new IOException(e.getMessage());
		} catch (DataFormatException e) {
			throw new IOException(e.getMessage());
		} catch (DuplicateNameException e) {
			throw new IOException(e.getMessage());
		} catch (InvalidInputException e) {
			throw new IOException(e.getMessage());
		}
	}

}
