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
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
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
		} catch (ElfException e) {
			throw new IOException(e.getMessage());
		} catch (CancelledException e) {
			// TODO: Caller should properly handle CancelledException instead
			throw new IOException(e.getMessage());
		} catch (DataFormatException e) {
			throw new IOException(e.getMessage());
		}
	}

}
