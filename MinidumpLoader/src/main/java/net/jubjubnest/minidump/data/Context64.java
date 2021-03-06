package net.jubjubnest.minidump.data;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

/**
 * 64-bit CPU context
 * 
 * https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
 */
public class Context64 implements ThreadContext {

	public static final int CONTEXT_TYPE = 1;
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

	public static Context64 parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	@Override
	public int getType() {
		return CONTEXT_TYPE;
	}

	public static ThreadContext fromBytes(byte[] bytes) {
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	@Override
	public byte[] toBytes() {

		ByteBuffer buffer = ByteBuffer.allocate(1200);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		
		buffer.putLong(p1Home);
		buffer.putLong(p2Home);
		buffer.putLong(p3Home);
		buffer.putLong(p4Home);
		buffer.putLong(p5Home);
		buffer.putLong(p6Home);
		
		buffer.putInt(contextFlags);
		buffer.putInt(mxCsr);
		
		buffer.putShort(segCs);
		buffer.putShort(segDs);
		buffer.putShort(segEs);
		buffer.putShort(segFs);
		buffer.putShort(segGs);
		buffer.putShort(segSs);
		buffer.putInt(eFlags);

		buffer.putLong(dr0);
		buffer.putLong(dr1);
		buffer.putLong(dr2);
		buffer.putLong(dr3);
		buffer.putLong(dr6);
		buffer.putLong(dr7);

		buffer.putLong(rax);
		buffer.putLong(rcx);
		buffer.putLong(rdx);
		buffer.putLong(rbx);
		buffer.putLong(rsp);
		buffer.putLong(rbp);
		buffer.putLong(rsi);
		buffer.putLong(rdi);
		buffer.putLong(r8);
		buffer.putLong(r9);
		buffer.putLong(r10);
		buffer.putLong(r11);
		buffer.putLong(r12);
		buffer.putLong(r13);
		buffer.putLong(r14);
		buffer.putLong(r15);
		
		buffer.putLong(rip);
		
		buffer.put(xmms);

		buffer.put(vectorRegister);
		buffer.putLong(vectorControl);

		buffer.putLong(debugControl);
		buffer.putLong(lastBranchToRip);
		buffer.putLong(lastBranchFromRip);
		buffer.putLong(lastExceptionToRip);
		buffer.putLong(lastExceptionFromRip);

		return buffer.array();
	}

	public static Context64 parse(ByteBuffer byteBuffer) {
		var ctx = new Context64();

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
