package net.jubjubnest.minidump.plugin;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.table.TableColumnModel;

import docking.widgets.table.GTable;
import ghidra.program.model.listing.Program;

public class ModulesList extends GTable {
	
	private ThreadViewPlugin plugin;
	private List<ModuleState> items;
	private ModulesTableModel model;
	
	public ModulesList(ThreadViewPlugin plugin) {
		this.plugin = plugin;
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
