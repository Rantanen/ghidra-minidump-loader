package net.jubjubnest.minidump.shared;

import java.util.ArrayList;
import java.util.List;

import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

public class SubTaskMonitor extends WrappingTaskMonitor {
	
	private String title;
	private String message;
	
	private List<RegexRule> replaceRules = new ArrayList<>();
	
	static class RegexRule {
		public RegexRule(String pattern, String replace) {
			this.pattern = pattern;
			this.replace = replace;
		}

		public String pattern;
		public String replace;
	}

	public SubTaskMonitor(String title, TaskMonitor delegate) {
		this(title, null, delegate);
	}

	public SubTaskMonitor(String title, String message, TaskMonitor delegate) {
		super(delegate);
		this.title = title;
		this.message = message;
		updateMessage();
	}
	
	public void addReplaceRule(String pattern, String replace) {
		this.replaceRules.add(new RegexRule(pattern, replace));
	}

	public void setMessage(String message) {
		this.message = message;
		updateMessage();
	}
	
	@Override
	public String getMessage() {
		return message;
	}
	
	private void updateMessage() {
		StringBuilder builder = new StringBuilder(this.title);
		if (message != null) {
			String replacedMessage = message;
			for (RegexRule rule : replaceRules) {
				replacedMessage = replacedMessage.replaceAll(rule.pattern, rule.replace);
			}
			builder.append(": ").append(replacedMessage);
		} else {
			builder.append("...");
		}
		
		super.setMessage(builder.toString());
	}
}
