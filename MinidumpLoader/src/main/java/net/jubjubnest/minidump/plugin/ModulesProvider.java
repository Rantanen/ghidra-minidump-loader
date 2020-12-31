package net.jubjubnest.minidump.plugin;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.CodeUnitPropertyChangeRecord;
import net.jubjubnest.minidump.shared.ModuleData;
import resources.Icons;

public class ModulesProvider extends ComponentProvider implements DomainObjectListener {
	
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

		table = new ModulesList();

		panel = new JPanel(new BorderLayout());
		panel.add(table);
		setVisible(true);
	}
	
	static int counter = 0;

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("Load Located Symbols", getName()) {
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
					navigateModule(table.getSelectedRow());
				}
			}
		});
	}
	
	public void programActivated(Program newProgram) {
		if (this.program != null) {
			this.program.removeListener(this);
		}

		this.program = newProgram;
		
		if (this.program != null) {
			this.program.addListener(this);
		}

		refreshModules();
	}

	void navigateModule(int idx) {
		var module = table.getModule(idx);
		if (module == null)
			return;
		plugin.goToService.goTo(module.baseAddress);
	}

	public void refreshModules() {
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

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!ev.containsEvent(ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED)) {
			return;
		}
		
		for (DomainObjectChangeRecord e : ev) {
			switch (e.getEventType()) {
			case ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED:
				CodeUnitPropertyChangeRecord propChange = (CodeUnitPropertyChangeRecord)e;
				if (propChange.getPropertyName().equals(ModuleData.PROPERTY_NAME)) {
					refreshModules();
				}
				break;
			}
		}
	}
}
