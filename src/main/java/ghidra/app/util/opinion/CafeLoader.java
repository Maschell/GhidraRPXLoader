package ghidra.app.util.opinion;

import cafeloader.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.zip.DataFormatException;

import generic.continues.GenericFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CafeLoader extends ElfLoader {
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		byte[] header = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x02, 0x01, (byte) 0xCA, (byte) 0xFE };
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (Arrays.equals(provider.readBytes(0, header.length), header)) {
			List<QueryResult> results = QueryOpinionService.query(getName(), "wiiu", null);
			boolean hasGekkoProcessor = false;

			for (QueryResult result : results) {
				if (result.pair.languageID.getIdAsString().contains("Gekko")) {
					hasGekkoProcessor = true;
				}
			}

			for (QueryResult result : results) {
				if (result.pair.languageID.getIdAsString().contains("Gekko")) {
					loadSpecs.add(new LoadSpec(this, 0, new QueryResult(result.pair, true)));
				} else {
					loadSpecs.add(new LoadSpec(this, 0, new QueryResult(result.pair, hasGekkoProcessor ? false : result.preferred)));
				}
			}

			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:32:default", "default"), true));
			}
		}

		return loadSpecs;
	}

	@Override
	public String getName() {
		return "Wii U / CafeOS Binary (RPX/RPL)";
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
			TaskMonitor monitor, MessageLog log) throws IOException {
		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			byte[] data = RplConverter.convertRpl(provider, monitor);
			RplHeader rpl = RplHeader.createRplHeader(factory, new ByteArrayProvider(data));
			ElfProgramBuilder.loadElf(rpl, program, options, log, monitor);
		} catch (ElfException e) {
			throw new IOException(e.getMessage());
		} catch (CancelledException e) {
			throw new IOException(e.getMessage());
		} catch (DataFormatException e) {
			throw new IOException(e.getMessage());
		}
	}
}
