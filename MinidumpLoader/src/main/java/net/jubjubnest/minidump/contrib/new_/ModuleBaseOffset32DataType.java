package net.jubjubnest.minidump.contrib.new_;

import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class ModuleBaseOffset32DataType extends AbstractModuleBaseOffsetDataType {
	
	private static DataType datatype = DWordDataType.dataType;
	public ModuleBaseOffset32DataType() {
		this(null);
	}
	
	public ModuleBaseOffset32DataType(DataTypeManager dtm) {
		super(null, generateName(datatype), dtm);
	}

	@Override
	DataType getScalarDataType() {
		return datatype;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		
		return new ModuleBaseOffset32DataType(dtm);
	}
}
