#pragma once
#include <Windows.h>

#ifdef _DEBUG
   #include <stdio.h>
   #include <stdlib.h>

   #define WIDE2(x) L##x
   #define WIDE1(x) WIDE2(x)
   #define WFILE WIDE1(__FILE__)

   /**
    * @brief Validates the process heap and reports unbalanced heap allocations.
     *
    * This helper is intended for debug-only shutdown checks for the tracked
    * HeapAlloc/HeapFree wrappers used by the implant template.
    *
    * @return VOID
    */
   VOID CheckHeapBalance(VOID);

   /**
    * @brief Writes a formatted debug message to the console in debug builds.
    *
    * @param format The printf-style wide format string.
    * @param ... Additional arguments consumed by the format string.
    *
    * @return VOID
    */
   VOID DebugPrint(_Printf_format_string_ const wchar_t* format, ...);

   extern volatile LONG g_HeapAllocCount;

   /**
    * @brief Allocates zeroed heap memory and tracks the allocation in debug builds.
    *
    * @param size The number of bytes to allocate.
    * @param file The source file that requested the allocation.
    * @param line The source line that requested the allocation.
    *
    * @return A pointer to the allocated memory, or NULL on failure.
    */
   PVOID DebugHeapAlloc(SIZE_T size, PCWSTR file, DWORD line);

   /**
    * @brief Frees heap memory and updates debug allocation tracking.
    *
    * @param ptr The heap pointer to free. May be NULL.
    * @param file The source file requesting the free.
    * @param line The source line requesting the free.
    *
    * @return VOID
    */
   VOID DebugHeapFree(PVOID ptr, PCWSTR file, DWORD line);

   #define ASSERT(exp) \
      do { \
         if (!(exp)) { \
            DebugPrint(L"ASSERT FAILED: %ls (%ls:%d)", WIDE1(#exp), WFILE, __LINE__); \
            __debugbreak(); \
         } \
      } while (0)

   #define ImplantHeapAlloc(size) DebugHeapAlloc((size), WFILE, __LINE__)
   #define ImplantHeapFree(ptr) DebugHeapFree((ptr), WFILE, __LINE__)
#else
   #define CheckHeapBalance() ((void)0)
   #define DebugPrint(...) ((void)0)
   #define ASSERT(exp) ((void)0)
   #define ImplantHeapAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
   #define ImplantHeapFree(ptr) HeapFree(GetProcessHeap(), 0, (ptr))
#endif
