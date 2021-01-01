package net.jubjubnest.minidump.plugin;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

class StackListModel extends AbstractTableModel {
	
	private static final String[] HEADERS = new String[] {
		"Stack Frame",
		"Function",
		"Frame Size",
		"Module",
	};
	
	static class Item {
		StackListItem frame;
		String function;
	}
	private List<Item> items;

	public StackListModel(List<StackListItem> frames, Program program) {
		items = new ArrayList<>(frames.size());
		for (StackListItem f : frames) {
			Item item = new Item();
			item.frame = f;
			items.add(item);
		}

		updateAnalysis(program);
	}
	
	public void updateAnalysis(Program program) {
		int min = Integer.MAX_VALUE;
		int max = 0;

		for (int i = 0; i < items.size(); i++) {
			Item item = items.get(i);

			String newName = null;
			Function newFn = program.getListing().getFunctionContaining(item.frame.instructionPointer);
			if (newFn != null) {
				newName = newFn.getName();
			}
				
			if (newName != item.function) {
				item.function = newName;
				max = i;
				if (i < min) {
					min = i;
				}
			}
		}
		
		if (min != Integer.MAX_VALUE) {
			fireTableRowsUpdated(min, max);
		}
	}
	
	@Override
	public String getColumnName(int column) {
		return HEADERS[column];
	}

	@Override
	public int getRowCount() {
		return items.size();
	}

	@Override
	public int getColumnCount() {
		return 4;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {

		Item item = items.get(rowIndex);
		StackListItem frame = item.frame;

		switch (columnIndex) {
		case 0:
			return frame.stackPointer.toString();
		case 1:
			if (item.function != null)
				return item.function + " + " + Long.toHexString(frame.functionOffset);
			return frame.instructionPointer.subtract(frame.functionOffset) + " + " + Long.toHexString(frame.functionOffset);
		case 2:
			return Long.toString(frame.returnPointer.subtract(frame.stackPointer));
		case 3:
			return frame.module;
		}

		throw new IndexOutOfBoundsException();
	}
	
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}
}