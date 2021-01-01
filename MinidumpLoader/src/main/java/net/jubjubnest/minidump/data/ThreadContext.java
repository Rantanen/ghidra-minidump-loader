package net.jubjubnest.minidump.data;

public interface ThreadContext {

	public int getType();
	public byte[] toBytes();
}
