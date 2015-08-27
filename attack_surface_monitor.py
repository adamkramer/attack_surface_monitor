# attack_surface_monitor.py

import wmi
import psutil

# List of protected processes
protected_processes = ['iexplore.exe', 'winword.exe']

# Setup WMI instance
wmi_instance = wmi.WMI()
process_watcher = wmi_instance.Win32_Process.watch_for("creation")

# Constant monitoring loop
while True:
	
	# If we've identified a new process being launched
	new_process = process_watcher()
	
	# Identify process ID and parent process ID
	process = psutil.Process(new_process.ProcessId)
	parent = psutil.Process(new_process.ParentProcessId)
	
	# If the process is something other than a child of itself
	if process.exe() != parent.exe():
		
		# If the parent process name is in the list of protected processes
		if parent.name() in protected_processes:

			# Warn the user...
			print ("Warning: Protected process " + parent.name() + " has launched a child process") 
			print ("Info: Attempting to terminate process: " + process.name())
			
			# ...and terminate the process
			if process.is_running():
				process.terminate()
