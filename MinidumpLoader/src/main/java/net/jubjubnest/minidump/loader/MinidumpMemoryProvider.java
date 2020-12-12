package net.jubjubnest.minidump.loader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;

import ghidra.app.util.bin.ByteProvider;
import net.jubjubnest.minidump.loader.parser.Memory64Descriptor;
import net.jubjubnest.minidump.loader.parser.Memory64List;

public class MinidumpMemoryProvider implements ByteProvider {

	public MinidumpMemoryProvider(ByteProvider provider, Memory64List memoryList) {
		this.provider = provider;
		this.segments = new ArrayList<Memory64Descriptor>();
		this.segments.addAll(memoryList.descriptors);
		this.segments.sort((a, b) -> Long.signum(a.baseAddress - b.baseAddress));

		this.totalMemSize = 0;
		this.segmentStarts = new ArrayList<Long>();
		for (var s : segments) {
			if (s.baseAddress + s.segmentSize > totalMemSize)
				totalMemSize = s.baseAddress + s.segmentSize;
			this.segmentStarts.add(s.baseAddress - 1);
		}
	}

	ByteProvider provider;
	ArrayList<Memory64Descriptor> segments;
	ArrayList<Long> segmentStarts;
	long totalMemSize;

	@Override
	public File getFile() {
		return provider.getFile();
	}

	@Override
	public String getName() {
		return provider.getName();
	}

	@Override
	public String getAbsolutePath() {
		return provider.getAbsolutePath();
	}

	@Override
	public long length() throws IOException {
		return this.totalMemSize;
	}

	@Override
	public boolean isValidIndex(long index) {
		return index >= 0 && index <= this.totalMemSize;
	}

	@Override
	public void close() throws IOException {
		// Do nothing.
	}

	@Override
	public byte readByte(long index) throws IOException {
		return readBytes(index, 1)[0];
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		byte[] buffer = new byte[(int) length];

		var written = 0;
		while (written < length) {
			var tail = index + written;
			var remaining = length - written;

			int newlyWritten = this.fillBuffer(buffer, written, tail, (int) remaining);
			if (newlyWritten == -1)
				throw new IOException("EOF");
			written += newlyWritten;
		}

		return buffer;
	}

	private int fillBuffer(byte[] buffer, int dstOffset, long offset, int length) throws IOException {
		length = Integer.min(length, buffer.length);

		int idx = Collections.binarySearch(this.segmentStarts, offset);
		if (idx < 0)
			idx = -idx - 1;
		if (idx == 0)
			return -1;
		idx -= 1;
		var segment = this.segments.get(idx);

		var segmentOffset = offset - segment.baseAddress;
		var segmentAvailable = segment.segmentSize - segmentOffset;
		if (segmentAvailable <= 0)
			return -1;

		var write = (int) Long.min(segmentAvailable, length);

		var chunk = this.provider.readBytes(segment.dataOffset + segmentOffset, write);
		System.arraycopy(chunk, 0, buffer, dstOffset, write);
		return write;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		return new MemoryStream(this, index);
	}

	class MemoryStream extends InputStream {

		MemoryStream(MinidumpMemoryProvider provider, long index) {
			this.provider = provider;
			this.index = index;
		}

		MinidumpMemoryProvider provider;
		long index;

		@Override
		public int read() throws IOException {
			int i = provider.readByte(this.index);
			this.index += 1;
			return i;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (b == null)
				throw new NullPointerException();
			if (off < 0 || len < 0 || len > b.length - off)
				throw new IndexOutOfBoundsException();

			int written = provider.fillBuffer(b, off, this.index, len);
			if (written != -1)
				this.index += written;
			return written;
		}
	}
}
