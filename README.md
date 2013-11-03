Ring3 rootkits - Base
========

Simple example of ring3 rootkits , this is only an example of the base of ring3 rootkits
it's not ready to use in good or bad way , there's also a list of api's the ring3 rootkits hits usually


	/* do another hooks .. .> 
	  # NtOpenProcess
	  # NtTerminateProcess
	  # GetExtendedTcpTable
	  # NtQueryInformationProcess
	  # RegEnumValue
	  # FindNextFile
	  # NtCreateFile
	   ... Etc ...
	*/
	
	in this exmaple i have used my hook method 'uncHook' method to detour the api 
	# Only OpenProcess api is hooked in this example .
