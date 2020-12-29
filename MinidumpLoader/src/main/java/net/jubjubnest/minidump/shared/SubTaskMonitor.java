package net.jubjubnest.minidump.shared;

import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

public class SubTaskMonitor extends WrappingTaskMonitor {
	
	private String title;
	private long maximum = 0;
	private long progress = 0;
	private String message;
	
	private String stripPrefix;

	public SubTaskMonitor(String title, TaskMonitor delegate) {
		this(title, null, delegate);
	}

	public SubTaskMonitor(String title, String message, TaskMonitor delegate) {
		super(delegate);
		this.title = title;
		this.message = message;
		updateMessage();
	}
	
	public void setStripPrefix(String prefix) {
		stripPrefix = prefix;
	}
	
	@Override
	public long getMaximum() {
		return maximum;
	}
	
	@Override
	public void initialize(long max) {
		progress = 0;
		maximum = max;
		updateMessage();
	}
	
	@Override
	public synchronized void setMaximum(long max) {
		maximum = max;
		updateMessage();
	}
	
	@Override
	public long getProgress() {
		return progress;
	}
	
	@Override
	public void setProgress(long value) {
		progress = value;
		updateMessage();
	}
	
	@Override
	public void incrementProgress(long incrementAmount) {
		progress += incrementAmount;
		updateMessage();
	}
	
	public void setMessage(String message) {
		if (stripPrefix != null && message.startsWith(stripPrefix)) {
			message = message.substring(stripPrefix.length());
		}

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
			builder.append(": ").append(message);
		} else {
			builder.append("...");
		}
		
		if (maximum > 0) {
			builder.append(" (").append(progress).append('/').append(maximum).append(')');
		}
		
		super.setMessage(builder.toString());
	}
}
