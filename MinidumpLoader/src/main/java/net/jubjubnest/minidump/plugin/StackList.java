package net.jubjubnest.minidump.plugin;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.table.TableColumnModel;

import docking.widgets.table.GTable;
import ghidra.program.model.listing.Program;

class StackList extends GTable {
	
	private ThreadViewPlugin plugin;
	private List<StackListItem> frames;
	private StackListModel model;
	
	public StackList(ThreadViewPlugin plugin) {
		this.plugin = plugin;

		this.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					boolean goToStack = StackList.this.getSelectedColumn() == 0;
					navigateStack(StackList.this.getSelectedRow(), goToStack);
				}
			}
		});
	}
	
	public void setFrames(List<StackListItem> frames, Program program) {

		this.frames = frames;
		model = new StackListModel(frames, program);
		this.setModel(model);
		TableColumnModel columns = getColumnModel();
		columns.getColumn(0).setPreferredWidth(100);
		columns.getColumn(1).setPreferredWidth(1000);
		columns.getColumn(2).setPreferredWidth(100);
		columns.getColumn(3).setPreferredWidth(100);
	}
	
	public void updateAnalysis(Program program) {
		if (model != null) {
			model.updateAnalysis(program);
		}
	}
	
	private void navigateStack(int item, boolean goToStack) {
		var frame = frames.get(item);
		if (frame == null)
			return;
		if (goToStack) {
			plugin.goToService.goTo(frame.stackPointer);
		} else {
			plugin.goToService.goTo(frame.instructionPointer);
		}
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
