/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.jubjubnest.minidump.plugin;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MinidumpPluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Displays Minidump Thread information.",
	description = "Lists Thread information contained in the Minidump and resolves the call stacks for each thread."
)
//@formatter:on
public class ThreadViewPlugin extends ProgramPlugin {

	ThreadViewProvider threadsProvider;
	GoToService goToService;
	Program program;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public ThreadViewPlugin(PluginTool tool) {
		super(tool, false, false);
		threadsProvider = new ThreadViewProvider(this, getName());
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
			threadsProvider.programActivated(program);
		}
	}
}
