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
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
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
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
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
						loadSymbols(table.getSelectedRow());
					} else {
						navigateModule(table.getSelectedRow());
					}
				}
			}
		});
	}
	
	public void programActivated(Program program) {
		this.program = program;
		refreshModules();
	}

	void navigateModule(int idx) {
		var module = table.getModule(idx);
		if (module == null)
			return;
		plugin.goToService.goTo(module.baseAddress);
	}
	
	void loadSymbols(int idx) {
		var module = table.getModule(idx);
		if (module == null)
			return;

		int tx = program.startTransaction("PDB");
		try {
			boolean analyzed = program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false);
			ModuleParser.PdbInfo pdbInfo = ModuleParser.getPdbInfo(program, module.baseAddress);
			PdbProgramAttributes pdbAttributes = new PdbProgramAttributes(
					pdbInfo.guid, Integer.toString(pdbInfo.age),
					false, analyzed, null, pdbInfo.pdbName, "RSDS");
			PdbLocator locator = new PdbLocator(PdbLocator.DEFAULT_SYMBOLS_DIR);
			String pdbPath = locator.findPdb(program, pdbAttributes, true, true, TaskMonitorAdapter.DUMMY, new MessageLog(), "???");

			GhidraFileChooser pdbChooser = new GhidraFileChooser(plugin.getTool().getToolFrame());
			pdbChooser.setTitle("Select PDB file to load:");
			pdbChooser.setApproveButtonText("Select PDB");
			pdbChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb", "xml" },
				"Program Database Files and PDB XML Representations"));

			if (pdbPath != null) {
				pdbChooser.setSelectedFile(new File(pdbPath));
			}

			File selectedPdb = pdbChooser.getSelectedFile();

			var pdb = PdbParser.parse(selectedPdb.getAbsolutePath(), new PdbReaderOptions(), TaskMonitorAdapter.DUMMY);
			pdb.deserialize(TaskMonitorAdapter.DUMMY);

			PdbApplicator applicator = new PdbApplicator(selectedPdb.getAbsolutePath(), pdb);
			applicator.applyTo(program, null, module.baseAddress, null,
					TaskMonitorAdapter.DUMMY, new MessageLog());

			program.endTransaction(tx, true);
		} catch (IOException | CancelledException | PdbException | MemoryAccessException e) {
			program.endTransaction(tx, false);
			e.printStackTrace();
		}
		/*
		try {
			var locator = new PdbLocator(null);
			var locatorAttribs = new PdbProgramAttributes
			locator.findPdb(program,)
			var pdb = PdbParser.parse("C:\\Users\\Rantanen\\source\\repos\\MinidumpTarget\\x64\\Release\\MinidumpTarget.pdb",
					new PdbReaderOptions(),
					TaskMonitorAdapter.DUMMY);
			pdb.deserialize(TaskMonitorAdapter.DUMMY);
			// pdb.getIdentifiers();
			PdbApplicator applicator = new PdbApplicator(
					"C:\\Users\\Rantanen\\source\\repos\\MinidumpTarget\\x64\\Release\\MinidumpTarget.pdb",
					pdb);
			applicator.applyTo(program, null, program.getImageBase().getNewAddress(0x7ff6a4930000l), null, TaskMonitorAdapter.DUMMY, new MessageLog());
			/*
			PdbProgramAttributes attribs = new PdbProgramAttributes(
					"4c7a5390-6613-4653-9a75-c06d855d8ff1",
					"2",
					false,
					false,
					null,
					"target.pdb",
					"none.exe");
			program.endTransaction(tx, true);
		} catch (CancelledException | PdbException | IOException e) {
			program.endTransaction(tx, false);
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
	}
	
	private void refreshModules() {
		if (program == null) {
			this.table.setModel(new ModulesTableModel(new ArrayList<>()));
			return;
		}
		
		List<ModuleData> moduleData = ModuleData.getAllModules(program);
		if (moduleData == null)
			return;
		
		List<ModuleState> items = new ArrayList<>();
		for (ModuleData md : moduleData) {
			items.add(new ModuleState(program, md));
		}
		this.table.setFrames(items, program);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
