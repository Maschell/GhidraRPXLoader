package ghidra.app.util.opinion;

import cafeloader.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.zip.DataFormatException;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CafeLoader extends ElfLoader {
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] header = new byte[]{0x7F, 0x45, 0x4C, 0x46, 0x01, 0x02, 0x01, (byte) 0xCA, (byte) 0xFE};
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
    public void load(Program program, Loader.ImporterSettings settings) throws IOException, CancelledException {
        try {
            byte[] data = RplConverter.convertRpl(settings.provider(), (msg) -> settings.log().appendMsg(msg));
            RplHeader rpl = new RplHeader(new ByteArrayProvider(data), (msg) -> settings.log().appendMsg(msg));
            ElfProgramBuilder.loadElf(rpl, program, settings.options(), settings.log(), settings.monitor());
        } catch (ElfException | DataFormatException var8) {
            throw new IOException(var8.getMessage());
        }
    }


    public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
                     TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

    }
}
