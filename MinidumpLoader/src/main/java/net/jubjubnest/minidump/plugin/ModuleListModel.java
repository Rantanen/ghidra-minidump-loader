package net.jubjubnest.minidump.plugin;

import java.util.List;

import javax.swing.table.AbstractTableModel;

import ghidra.util.exception.NotYetImplementedException;

class ModuleListModel extends AbstractTableModel {
	
	private List<ModuleListItem> items;
	private String[] headers = new String[] {
		"Name",
		"Symbols",
	};
	
	public ModuleListModel(List<ModuleListItem> items) {
		this.items = items;
	}
	
	@Override
	public String getColumnName(int column) {
		return headers[column];
	}

	@Override
	public int getRowCount() {
		return items.size();
	}

	@Override
	public int getColumnCount() {
		return 2;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		ModuleListItem item = items.get(rowIndex);
		
		switch (columnIndex) {
		case 0:
			return item.name;
		case 1:
			if (item.symbolPath == null) {
				return "No symbols";
			}
			
			if (item.symbolsLoaded) {
				return "Loaded: " + item.symbolPath;
			}
			return "Located: " + item.symbolPath;
		default:
			throw new NotYetImplementedException();
		}
	}

}
