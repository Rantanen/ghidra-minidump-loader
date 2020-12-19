package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public class ContextX64 {

	public static final int RECORD_SIZE = 
			6 * 8 +
			2 * 4 +
			6 * 2 + 4 +
			6 * 8 +
			16 * 8 +
			8 + 
			18 * 16 +
			26 * 16 + 8 +
			5 * 8;

	public static ContextX64 parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	public static ContextX64 parse(ByteBuffer byteBuffer) {
		var ctx = new ContextX64();

		ctx.p1Home = byteBuffer.getLong();
		ctx.p2Home = byteBuffer.getLong();
		ctx.p3Home = byteBuffer.getLong();
		ctx.p4Home = byteBuffer.getLong();
		ctx.p5Home = byteBuffer.getLong();
		ctx.p6Home = byteBuffer.getLong();

		ctx.contextFlags = byteBuffer.getInt();
		ctx.mxCsr = byteBuffer.getInt();

		ctx.segCs = byteBuffer.getShort();
		ctx.segDs = byteBuffer.getShort();
		ctx.segEs = byteBuffer.getShort();
		ctx.segFs = byteBuffer.getShort();
		ctx.segGs = byteBuffer.getShort();
		ctx.segSs = byteBuffer.getShort();
		ctx.eFlags = byteBuffer.getInt();

		ctx.dr0 = byteBuffer.getLong();
		ctx.dr1 = byteBuffer.getLong();
		ctx.dr2 = byteBuffer.getLong();
		ctx.dr3 = byteBuffer.getLong();
		ctx.dr6 = byteBuffer.getLong();
		ctx.dr7 = byteBuffer.getLong();

		ctx.rax = byteBuffer.getLong();
		ctx.rcx = byteBuffer.getLong();
		ctx.rdx = byteBuffer.getLong();
		ctx.rbx = byteBuffer.getLong();
		ctx.rsp = byteBuffer.getLong();
		ctx.rbp = byteBuffer.getLong();
		ctx.rsi = byteBuffer.getLong();
		ctx.rdi = byteBuffer.getLong();
		ctx.r8 = byteBuffer.getLong();
		ctx.r9 = byteBuffer.getLong();
		ctx.r10 = byteBuffer.getLong();
		ctx.r11 = byteBuffer.getLong();
		ctx.r12 = byteBuffer.getLong();
		ctx.r13 = byteBuffer.getLong();
		ctx.r14 = byteBuffer.getLong();
		ctx.r15 = byteBuffer.getLong();
		
		ctx.rip = byteBuffer.getLong();
		
		ctx.xmms = new byte[18 * 16];
		for( int i = 0; i < ctx.xmms.length; i++)
			ctx.xmms[i] = byteBuffer.get();

		ctx.vectorRegister = new byte[26 * 16];
		for( int i = 0; i < ctx.vectorRegister.length; i++)
			ctx.vectorRegister[i] = byteBuffer.get();
		ctx.vectorControl = byteBuffer.getLong();

		ctx.debugControl = byteBuffer.getLong();
		ctx.lastBranchToRip = byteBuffer.getLong();
		ctx.lastBranchFromRip = byteBuffer.getLong();
		ctx.lastExceptionToRip = byteBuffer.getLong();
		ctx.lastExceptionFromRip = byteBuffer.getLong();

		return ctx;
	}

	public long p1Home;
	public long p2Home;
	public long p3Home;
	public long p4Home;
	public long p5Home;
	public long p6Home;
	
	public int contextFlags;
	public int mxCsr;
	
	public short segCs;
	public short segDs;
	public short segEs;
	public short segFs;
	public short segGs;
	public short segSs;
	public int eFlags;
	
	public long dr0;
	public long dr1;
	public long dr2;
	public long dr3;
	public long dr6;
	public long dr7;
	
	public long rax;
	public long rcx;
	public long rdx;
	public long rbx;
	public long rsp;
	public long rbp;
	public long rsi;
	public long rdi;
	public long r8;
	public long r9;
	public long r10;
	public long r11;
	public long r12;
	public long r13;
	public long r14;
	public long r15;
	
	public long rip;
	
	// 18 x 128-bit registers.
	public byte xmms[];
	
	// 26 x 128-bit register
	public byte vectorRegister[];
	public long vectorControl;
	
	public long debugControl;
	public long lastBranchToRip;
	public long lastBranchFromRip;
	public long lastExceptionToRip;
	public long lastExceptionFromRip;
}
