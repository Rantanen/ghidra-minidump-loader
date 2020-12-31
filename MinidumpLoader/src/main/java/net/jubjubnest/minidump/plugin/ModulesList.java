package net.jubjubnest.minidump.plugin;

import java.util.List;

import docking.widgets.table.GTable;
import ghidra.program.model.listing.Program;

public class ModulesList extends GTable {
	
	private List<ModuleState> items;
	private ModulesTableModel model;
	
	public ModulesList() {
	}
	
	public void setFrames(List<ModuleState> items, Program program) {

		this.items = items;
		model = new ModulesTableModel(items);
		this.setModel(model);
	}
	
	public ModuleState getModule(int idx) {
		return items.get(idx);
	}

	@Override
	public boolean isCellEditable(int row, int column) {
		return false;
	}
	
	@Override
	public boolean getColumnSelectionAllowed() {
		return false;
	}
}
