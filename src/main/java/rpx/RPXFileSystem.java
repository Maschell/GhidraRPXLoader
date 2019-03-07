/****************************************************************************
 * Copyright (C) 2019 Maschell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/
package rpx;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.apache.commons.collections4.map.HashedMap;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 */
@FileSystemInfo(type = "rpx", description = "RPX", factory = RPXFileSystem.RPXFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class RPXFileSystem implements GFileSystem {

	private static byte[] RPX_MAGIC = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x02, 0x01, (byte) 0xCA, (byte) 0xFE };
	public static final int SHF_RPL_ZLIB = 0x08000000;
	public static final int SHT_NOBITS = 0x00000008;

	public static final int SHT_RPL_CRCS = 0x80000003;
	public static final int SHT_RPL_FILEINFO = 0x80000004;

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<ElfData> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL   The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public RPXFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + RPXFileSystem.class.getSimpleName() + "...");
		try {
			ElfData data = convertRPX(provider);
			fsih.storeFile("converted.elf", 0, false, data.elf_size, data);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Based on https://github.com/Relys/rpl2elf/blob/master/rpl2elf.c
	 * 
	 * @return
	 */
	public static ElfData convertRPX(ByteProvider bProvider) throws ElfException, IOException, DataFormatException {
		ElfHeader elfFile = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, bProvider);
		elfFile.parse();

		ByteBuffer buffer = ByteBuffer.allocate(0);

		int section_count = 0;
		for (ElfSectionHeader h : elfFile.getSections()) {
			if (h.getType() == SHT_RPL_CRCS || h.getType() == SHT_RPL_FILEINFO) {
				continue;
			}
			section_count++;
		}

		long shdr_elf_offset = elfFile.e_ehsize() & 0xFFFFFFFF;
		long shdr_data_elf_offset = shdr_elf_offset + section_count * elfFile.e_shentsize();

		for (ElfSectionHeader h : elfFile.getSections()) {

			long curSize = h.getSize();
			long flags = h.getFlags();
			long offset = h.getOffset();

			if (offset != 0) {
				if ((flags & SHT_NOBITS) != SHT_NOBITS) {
					byte[] data = h.getData();

					if ((flags & SHF_RPL_ZLIB) == SHF_RPL_ZLIB) {
						long section_size_inflated = ByteBuffer.wrap(Arrays.copyOf(data, 4)).getInt() & 0xFFFFFFFF;
						Inflater inflater = new Inflater();
						inflater.setInput(data, 4, (int) h.getSize() - 4); // the first byte is the size

						byte[] decompressed = new byte[(int) section_size_inflated];

						inflater.inflate(decompressed);

						inflater.end();

						curSize = section_size_inflated & ~0x3;
						flags &= ~SHF_RPL_ZLIB;
						data = decompressed;
					}
					long newEnd = shdr_data_elf_offset + curSize;

					if (h.getType() == SHT_RPL_CRCS || h.getType() == SHT_RPL_FILEINFO) {
						System.out.println("Skip special section " + h.getTypeAsString());
						continue;
					}

					System.out.println("Saving " + h.getTypeAsString());

					buffer = checkBuffer(buffer, newEnd);
					buffer.position((int) shdr_data_elf_offset);
					System.out.println("Write data " + String.format("%08X", shdr_data_elf_offset));
					buffer.put(data);
					offset = shdr_data_elf_offset;
					shdr_data_elf_offset += curSize;
				}
			}
			buffer = checkBuffer(buffer, shdr_elf_offset + 0x28);

			buffer.position((int) shdr_elf_offset);
			buffer.putInt(h.getName());
			buffer.putInt(h.getType());
			buffer.putInt((int) flags);
			buffer.putInt((int) h.getAddress());
			buffer.putInt((int) offset);
			buffer.putInt((int) curSize);
			buffer.putInt(h.getLink());
			buffer.putInt(h.getInfo());
			buffer.putInt((int) h.getAddressAlignment());
			buffer.putInt((int) h.getEntrySize());

			shdr_elf_offset += 0x28;

		}

		buffer.position(0);
		buffer.put(RPX_MAGIC);
		buffer.position(0x10);
		buffer.putShort((short) 0x02); // e.e_type());
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

		byte[] dataArray = buffer.array();

		return new ElfData(dataArray, (int) bProvider.length());
	}

	private static ByteBuffer checkBuffer(ByteBuffer buffer, long newEnd) {
		// This probably the worst way to do this.
		if (buffer.remaining() < newEnd) {
			ByteBuffer newBuffer = ByteBuffer.allocate((int) (buffer.capacity() + newEnd - buffer.remaining()));
			newBuffer.put(buffer.array());
			return newBuffer;
		}
		return buffer;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
		ElfData metadata = fsih.getMetadata(file);
		return (metadata != null) ? new ByteArrayInputStream(metadata.data) : null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) throws IOException {
		ElfData metadata = fsih.getMetadata(file);
		return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
	}

	private Map<String, String> getInfoMap(ElfData metadata) {
		Map<String, String> infos = new HashedMap<>();
		infos.put("elf_size", Integer.toString(metadata.elf_size));
		infos.put("rpx_size", Integer.toString(metadata.rpx_size));
		return infos;
	}

	public static class RPXFileSystemFactory implements GFileSystemFactoryFull<RPXFileSystem>, GFileSystemProbeFull {
		@Override
		public RPXFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider byteProvider,
				File containerFile, FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			RPXFileSystem fs = new RPXFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {
			byte[] header = byteProvider.readBytes(0, RPX_MAGIC.length);
			return Arrays.equals(header, RPX_MAGIC);
		}
	}

	private static class ElfData {
		private byte[] data;
		private int elf_size;
		private int rpx_size;

		public ElfData(byte[] data, int rpx_size) {
			this.data = data;
			this.elf_size = data.length;
			this.rpx_size = rpx_size;
		}
	}
}
