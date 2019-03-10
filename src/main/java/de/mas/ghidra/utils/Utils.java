package de.mas.ghidra.utils;

import java.nio.ByteBuffer;

public class Utils {
	private Utils() {
	}

	/**
	 * Grows a ByteBuffer if needed.
	 * 
	 * @param buffer the original buffer
	 * @param size   the needed size.
	 * @return A byte buffer with the expected size. If the buffer was big enough,
	 *         the original buffer will be returned, otherwise a new one will be
	 *         created.
	 */
	public static ByteBuffer checkAndGrowByteBuffer(ByteBuffer buffer, long size) {
		// This probably the worst way to do this.
		if (buffer.remaining() < size) {
			ByteBuffer newBuffer = ByteBuffer.allocate((int) (buffer.capacity() + size - buffer.remaining()));
			newBuffer.put(buffer.array());
			return newBuffer;
		}
		return buffer;
	}

	public static String stringFromStringTable(byte[] stringTable, int index) {
		ByteBuffer buf = ByteBuffer.wrap(stringTable);

		int pos = index;

		StringBuilder result = new StringBuilder();

		for (byte b; (b = buf.get(pos)) != 0; pos++) {
			result.append((char) b);
		}

		return result.toString();
	}
}
