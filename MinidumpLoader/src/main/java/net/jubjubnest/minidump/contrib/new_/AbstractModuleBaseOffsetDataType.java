package net.jubjubnest.minidump.contrib.new_;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

abstract class AbstractModuleBaseOffsetDataType extends BuiltIn {
	
	public AbstractModuleBaseOffsetDataType(CategoryPath path, String name, DataTypeManager dtm) {
		super(path, name, dtm);
	}
	
	abstract DataType getScalarDataType();
	
	static String generateName(DataType dt) {
		return "ModuleBaseOffset" + dt.getLength() * 8;
	}
	
	static String generateMnemonic(DataType dt) {
		return "mbo" + dt.getLength() * 8;
	}
	
	static String generateDescription(DataType dt) {
		return (dt.getLength() * 8) + "-bit Module Base Offset";
	}
	
	@Override
	public String getDescription() {
		DataType dt = getScalarDataType();
		return generateDescription(dt);
	}
	
	@Override
	public String getMnemonic(Settings settings) {
		DataType dt = getScalarDataType();
		return generateMnemonic(dt);
	}

	@Override
	public int getLength() {
		return getScalarDataType().getLength();
	}
	
	@Override
	public boolean hasLanguageDependantLength() {
		return false;
	}
	
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Address addr = (Address) getValue(buf, settings, length);
		if (addr == null)
			return "NaP";
		return addr.toString();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		Address moduleBase = ModuleBaseMap.getModuleBase(buf.getMemory().getProgram(), buf.getAddress());
		if (moduleBase == null) {
			return null;
		}
		
		Scalar value = (Scalar) getScalarDataType().getValue(buf, settings, length);
		if (value == null || value.getUnsignedValue() == 0) {
			return null;
		}
		
		try {
			return moduleBase.add(value.getUnsignedValue());
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}
}
