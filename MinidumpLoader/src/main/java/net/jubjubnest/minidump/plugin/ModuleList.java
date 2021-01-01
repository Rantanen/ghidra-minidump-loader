package net.jubjubnest.minidump.plugin;

import java.util.List;

import docking.widgets.table.GTable;
import ghidra.program.model.listing.Program;

class ModuleList extends GTable {
	
	private List<ModuleListItem> items;
	private ModuleListModel model;
	
	public ModuleList() {
	}
	
	public void setFrames(List<ModuleListItem> items, Program program) {

		this.items = items;
		model = new ModuleListModel(items);
		this.setModel(model);
	}
	
	public ModuleListItem getModule(int idx) {
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
