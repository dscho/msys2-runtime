#include <stdio.h>
#include <windows.h>

/**
 * To determine the address of kernel32!CtrlRoutine, we need to use
 * dbghelp.dll. But we want to avoid linking statically to that library because
 * the normal operation of cygwin-console-helper.exe (i.e. to allocate a hidden
 * Console) does not need it.
 *
 * Therefore, we declare the SYMBOL_INFOW structure here, load the dbghelp
 * library via LoadLibraryExA() and obtain the SymInitialize(), SymFromAddrW()
 * and SymCleanup() functions via GetProcAddr().
 */

typedef struct {
  ULONG SizeOfStruct;
  ULONG TypeIndex;
  ULONG64 Reserved[2];
  ULONG info;
  ULONG Size;
  ULONG64 ModBase;
  ULONG Flags;
  ULONG64 Value;
  ULONG64 Address;
  ULONG Register;
  ULONG Scope;
  ULONG Tag;
  ULONG NameLen;
  ULONG MaxNameLen;
  WCHAR Name[1];
} *PSYMBOL_INFOW;
#define MAX_SYM_NAME 2000

/* Avoid fprintf(), as it would try to reference '__getreent' */
static void
output (BOOL error, const char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  va_start (ap, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, ap);
  buffer[sizeof(buffer) - 1] = '\0';
  va_end (ap);
  WriteFile (GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE),
	     buffer, strlen (buffer), NULL, NULL);
}

static WINAPI BOOL
ctrl_handler(DWORD ctrl_type)
{
  unsigned short count;
  void *address;
  HMODULE dbghelp;
  BOOL (*SymInitialize)(HANDLE, PCSTR, BOOL);
  BOOL (*SymFromAddrW)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFOW);
  BOOL (*SymCleanup)(HANDLE hProcess);
  HANDLE process;
  PSYMBOL_INFOW info;
  DWORD64 displacement;

  if (!(dbghelp = LoadLibraryExA ("dbghelp.dll", NULL,
				  LOAD_LIBRARY_SEARCH_SYSTEM32)) ||
      !(SymInitialize = (typeof(SymInitialize))
	GetProcAddress (dbghelp, "SymInitialize")) ||
      !(SymFromAddrW = (typeof(SymFromAddrW))
	GetProcAddress (dbghelp, "SymFromAddrW")) ||
      !(SymCleanup = (typeof(SymCleanup))
	GetProcAddress (dbghelp, "SymCleanup")))
    {
      output (1, "Could not load dbghelp\n");
      return FALSE;
    }

  count = CaptureStackBackTrace (1l /* skip this function */,
			         1l /* return only one trace item */,
				 &address, NULL);
  if (count != 1)
    {
      output (1, "Could not capture backtrace\n");
      return FALSE;
    }

  process = GetCurrentProcess ();
  if (!SymInitialize (process, NULL, TRUE))
    {
      output (1, "Could not initialize symbols\n");
      return FALSE;
    }

  info = (PSYMBOL_INFOW)
    malloc (sizeof(*info) + MAX_SYM_NAME * sizeof(wchar_t));
  if (!info)
    {
      output (1, "Could not allocate symbol info structure\n");
      return FALSE;
    }
  info->SizeOfStruct = sizeof(*info);
  info->MaxNameLen = MAX_SYM_NAME;

  if (!SymFromAddrW (process, (DWORD64)address, &displacement, info))
    {
      output (1, "Could not get symbol info\n");
      return FALSE;
    }
  output (0, "%p\n", (void *)info->Address);
  CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
  SymCleanup(process);

  exit(0);
}

int
main (int argc, char **argv)
{
  char *end;

  if (argc > 2 && !strcmp ("--get-address-of", argv[1]))
    {
      if (argc == 4 && !strcmp ("--alloc-console", argv[3]))
        {
	  if (!FreeConsole () && GetLastError () != ERROR_INVALID_PARAMETER)
	    {
	      output (1, "Could not detach from current Console: %d\n",
		      (int)GetLastError());
	      return 1;
	    }
	  if (!AllocConsole ())
	    {
	      output (1, "Could not allocate a new Console\n");
	      return 1;
	    }
	}
      else if (argc > 3)
        {
	  output (1, "Unhandled option: %s\n", argv[3]);
	  return 1;
	}

      if (strcmp(argv[2], "CtrlRoutine"))
        {
	  output (1, "Unhandled function name: %s\n", argv[2]);
	  return 1;
	}

      if (!SetConsoleCtrlHandler (ctrl_handler, TRUE))
        {
	  output (1, "Could not register Ctrl handler\n");
	  return 1;
	}

      if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0))
        {
	  output (1, "Could not simulate Ctrl+Break\n");
	  return 1;
	}

      /* Give the event 1sec time to print out the address */
      Sleep(1000);
      return 1;
    }

  if (argc != 3)
    exit (1);
  HANDLE h = (HANDLE) strtoul (argv[1], &end, 0);
  SetEvent (h);
  h = (HANDLE) strtoul (argv[2], &end, 0);
  WaitForSingleObject (h, INFINITE);
  exit (0);
}
