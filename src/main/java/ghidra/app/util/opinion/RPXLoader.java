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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
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
						Reference r = program.getReferenceManager().addExternalReference(addr, rplName,
								symbol.getNameAsString(), aspace.getAddress(0), SourceType.IMPORTED, 1, RefType.DATA);
						program.getReferenceManager().setPrimary(r, true);
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
