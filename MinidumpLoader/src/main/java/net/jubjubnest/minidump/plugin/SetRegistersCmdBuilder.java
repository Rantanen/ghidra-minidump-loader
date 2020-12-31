package net.jubjubnest.minidump.plugin;

import java.math.BigInteger;

import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class SetRegistersCmdBuilder {
	CompoundCmd cmds = new CompoundCmd("Set Register Values");
	Program program;
	Address address;
	
	public SetRegistersCmdBuilder(Program program, Address address) {
		this.program = program;
		this.address = address;
	}
	
	public void setRegister(String name, long value) {
		setRegister(name, BigInteger.valueOf(value));
	}

	public void setRegister(String name, BigInteger value) {
		Register reg = program.getLanguage().getRegister(name);
		cmds.add(new SetRegisterCmd(reg, address, address, value));
	}
	
	public Command getCommand() {
		return cmds;
	}
}
