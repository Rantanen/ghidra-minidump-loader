package net.jubjubnest.minidump.contrib.new_;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.QWordDataType;

public class ModuleBaseOffset64DataType extends AbstractModuleBaseOffsetDataType {
	
	private static DataType datatype = QWordDataType.dataType;
	public ModuleBaseOffset64DataType() {
		this(null);
	}
	
	public ModuleBaseOffset64DataType(DataTypeManager dtm) {
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
		
		return new ModuleBaseOffset64DataType(dtm);
	}
}
