package net.jubjubnest.minidump.loader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;

import org.bouncycastle.util.Arrays;

import ghidra.app.util.bin.ByteProvider;
import net.jubjubnest.minidump.loader.parser.MinidumpMemory64Descriptor;
import net.jubjubnest.minidump.loader.parser.MinidumpMemory64List;


/**
 * Byte provider that allows reading minidumps as virtual memory.
 *
 * The provider assumes the memory is infinite and uninitialized with zeros.
 * This allows other components to read memory as if it was contiguous even if
 * the minidump itself is missing certain memory pages.
 * 
 * Note that APIs such as 'length()' still return the total memory size.
 */
class MinidumpMemoryProvider implements ByteProvider {

	public MinidumpMemoryProvider(ByteProvider provider, MinidumpMemory64List memoryList) {
		this.provider = provider;
		this.segments = new ArrayList<MinidumpMemory64Descriptor>();
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
	ArrayList<MinidumpMemory64Descriptor> segments;
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

		// Find the segment.
		// The binary search will find the segment the start of which is at the given start or the last one before it.
		int idx = Collections.binarySearch(this.segmentStarts, offset);
		if (idx < 0)
			idx = -idx - 1;
		if (idx == 0)
			return -1;
		idx -= 1;
		var segment = this.segments.get(idx);

		// Check whether the found segment has bytes available for the given range.
		var segmentOffset = offset - segment.baseAddress;
		var segmentAvailable = segment.segmentSize - segmentOffset;
		if (segmentAvailable > 0)
		{
			// Bytes available. We should try to write as much as asked, but cap at the amount of bytes available.
			var bytesToWrite = (int) Long.min(segmentAvailable, length);
			var chunk = this.provider.readBytes(segment.dataOffset + segmentOffset, bytesToWrite);
			System.arraycopy(chunk, 0, buffer, dstOffset, bytesToWrite);
			return bytesToWrite;
		}
		else if( idx + 1 < this.segments.size() )
		{
			// No bytes available, but a next segment exists.
			// We'll assume the bytes from this segment to the next are 0.
			var nextSegment = this.segments.get(idx + 1);
			var bytesToNextSegment = nextSegment.baseAddress - offset;
			var bytesToWrite = (int) Long.min(bytesToNextSegment, length);
			Arrays.fill(buffer, 0, bytesToWrite, (byte)0);
			return bytesToWrite;
		}
		else
		{
			// No further segments.
			// Just keep returning zero bytes.
			Arrays.fill(buffer, 0, length, (byte)0);
			return length;
		}
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		return new MemoryStream(index);
	}

	class MemoryStream extends InputStream {

		MemoryStream(long index) {
			this.index = index;
		}

		long index;

		@Override
		public int read() throws IOException {
			int i = readByte(this.index);
			this.index += 1;
			return i;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (b == null)
				throw new NullPointerException();
			if (off < 0 || len < 0 || len > b.length - off)
				throw new IndexOutOfBoundsException();

			int written = fillBuffer(b, off, this.index, len);
			if (written != -1)
				this.index += written;
			return written;
		}
	}
}
