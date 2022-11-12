package cafeloader;

import java.lang.Throwable;
import java.util.function.Consumer;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;

public class RplHeader extends ElfHeader
{
	public RplHeader(ByteProvider provider, Consumer<String> errorConsumer) throws ElfException {
		super(provider, errorConsumer);
	}

	@Override
	public short e_machine() {
		// Hack to force use of Cafe_ElfRelocationHandler and Cafe_ElfExtension instead of PowerPC_*
		StackTraceElement[] trace = new Throwable().getStackTrace();
		if (trace.length >= 6 &&
			 ((trace[6].getClassName() == "ghidra.app.util.bin.format.elf.relocation.PowerPC_ElfRelocationHandler" &&
				trace[6].getMethodName() == "canRelocate") ||
			  (trace[6].getClassName() == "ghidra.app.util.bin.format.elf.extend.PowerPC_ElfExtension" &&
				trace[6].getMethodName() == "canHandle"))) {
			return 0;
		}

		return super.e_machine();
	}
}
