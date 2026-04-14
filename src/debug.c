#include "debug.h"

#ifdef _DEBUG

/* Tracks the number of debug heap allocations still outstanding at shutdown. */
volatile LONG g_HeapAllocCount = 0;

VOID CheckHeapBalance(VOID)
{
	if (!HeapValidate(GetProcessHeap(), 0, NULL))
	{
		DebugPrint(L"Heap validation failed");
	}

	if (g_HeapAllocCount != 0)
	{
		DebugPrint(L"Heap leak count: %ld", g_HeapAllocCount);
	}
}

VOID DebugPrint(const wchar_t* format, ...)
{
	va_list args;

	va_start(args, format);
	vwprintf(format, args);
	wprintf(L"\n");
	va_end(args);
}

PVOID DebugHeapAlloc(SIZE_T size, PCWSTR file, DWORD line)
{
	PVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

	if (buffer != NULL)
	{
		InterlockedIncrement(&g_HeapAllocCount);
		DebugPrint(L"HeapAlloc %p size=%zu (%ls:%lu)", buffer, size, file, line);
	}

	return buffer;
}

VOID DebugHeapFree(PVOID ptr, PCWSTR file, DWORD line)
{
	if (ptr != NULL)
	{
		HeapFree(GetProcessHeap(), 0, ptr);
		InterlockedDecrement(&g_HeapAllocCount);
		DebugPrint(L"HeapFree %p (%ls:%lu)", ptr, file, line);
	}
}

#endif
