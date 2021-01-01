package net.jubjubnest.minidump.plugin;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MinidumpPluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Display Minidump loaded module information.",
	description = "Display Minidump loaded module information."
)
//@formatter:on
public class ModuleViewPlugin extends ProgramPlugin {

	ModuleViewProvider modulesProvider;
	GoToService goToService;
	Program program;

	public ModuleViewPlugin(PluginTool tool) {
		super(tool, false, false);
		modulesProvider = new ModuleViewProvider(this, getName());
	}

	@Override
	public void init() {
		super.init();
		goToService = tool.getService(GoToService.class);
	}
	
	@Override
	public void processEvent(PluginEvent event)
	{
		if (event instanceof ProgramActivatedPluginEvent)
		{
			var ev = (ProgramActivatedPluginEvent)event;
			program = ev.getActiveProgram();
			modulesProvider.programActivated(program);
		}
	}
}
