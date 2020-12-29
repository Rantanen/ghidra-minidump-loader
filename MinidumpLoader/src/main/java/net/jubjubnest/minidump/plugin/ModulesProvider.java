package net.jubjubnest.minidump.plugin;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTable;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import net.jubjubnest.minidump.shared.ModuleData;
import resources.Icons;

public class ModulesProvider extends ComponentProvider {
	
	public static final String NAME = "Memory Dump Modules";
	
	private ThreadViewPlugin plugin;
	private JPanel panel;
	private ModulesList table;
	private Program program;
	private DockingAction action;

	public ModulesProvider(ThreadViewPlugin plugin, String owner) {
		super(plugin.getTool(), NAME, owner);
		this.plugin = plugin;

		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {

		table = new ModulesList(this.plugin);

		panel = new JPanel(new BorderLayout());
		panel.add(table);
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("Load Located Symbols", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				loadLocatedSymbols();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					if (table.getSelectedColumn() == 0) {
						locateSymbols(table.getSelectedRow());
					} else {
						navigateModule(table.getSelectedRow());
					}
				}
			}
		});
	}
	
	public void programActivated(Program program) {
		this.program = program;
		refreshModules(true);
	}
	
	public List<ModuleState> getModules() {
		return this.table.getModules();
	}

	void navigateModule(int idx) {
		var module = table.getModule(idx);
		if (module == null)
			return;
		plugin.goToService.goTo(module.baseAddress);
	}
	
	void locateSymbols(int idx) {
		var module = table.getModule(idx);
		if (module == null)
			return;
		
		TaskLauncher.launch(new LocatePdbTask(program, module, this));
	}
	
	protected void loadLocatedSymbols() {
		TaskLauncher.launch(new LoadPdbsTask(program, this));
	}

	public void refreshModules(boolean reload) {
		if (program == null) {
			this.table.setModel(new ModulesTableModel(new ArrayList<>()));
			return;
		}
		
		List<ModuleData> moduleData = ModuleData.getAllModules(program);
		if (moduleData == null)
			return;
		
		if (reload) {
			List<ModuleState> items = new ArrayList<>();
			for (ModuleData md : moduleData) {
				items.add(new ModuleState(program, md));
			}
			this.table.setFrames(items, program);
		} else {
			this.table.repaint();
		}
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
