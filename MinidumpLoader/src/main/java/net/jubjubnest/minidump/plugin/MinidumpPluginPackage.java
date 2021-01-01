package net.jubjubnest.minidump.plugin;

import javax.swing.Icon;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class MinidumpPluginPackage extends PluginPackage {
	public static final String NAME = "Minidump";

	protected MinidumpPluginPackage(String name, Icon icon, String description) {
		super(NAME, ResourceManager.loadImage("images/vcard.png"),
				"Plugins for working with Windows Minidump files.");
	}
}
