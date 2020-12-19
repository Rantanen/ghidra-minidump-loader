package net.jubjubnest.minidump.plugin;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.Tool;
import docking.widgets.table.GTable;
import ghidra.program.model.listing.Program;

public class ModulesProvider extends ComponentProvider {
	
	public static final String NAME = "Memory Dump Modules";
	
	private ThreadViewPlugin plugin;
	private GTable table;
	private ModulesTableModel model;
	private Program program;

	public ModulesProvider(ThreadViewPlugin plugin, String owner) {
		super(plugin.getTool(), NAME, owner);
		this.plugin = plugin;
		this.table = new GTable();
	}
	
	public void programActivated(Program program) {
		this.program = program;
		refreshModules();
	}
	
	private void refreshModules() {
		if (this.program == null) {
			this.table.setModel(new ModulesTableModel());
		}
	}

	@Override
	public JComponent getComponent() {
		return this.table;
	}

}
