#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <windows.h>

int
main (int argc, char **argv)
{
  void *llvm_base = (void *) (uintptr_t) 0x4d5df0000ULL;
  void *reserved;
  void *image;
  pid_t child;
  int status;

  if (argc != 2)
    return 2;

  reserved = VirtualAlloc (llvm_base, 0x4b0e000, MEM_RESERVE, PAGE_NOACCESS);
  if (reserved != llvm_base)
    {
      fprintf (stderr, "LLVM-range reservation failed: %lu\n",
               (unsigned long) GetLastError ());
      return 2;
    }

  image = dlopen (argv[1], RTLD_NOW);
  if (!image)
    {
      fprintf (stderr, "dlopen failed: %s\n", dlerror ());
      return 2;
    }
  printf ("DLL loaded at %p with LLVM's preferred range reserved\n", image);
  fflush (stdout);

  child = fork ();
  if (child < 0)
    {
      perror ("fork");
      return 1;
    }
  if (!child)
    _exit (0);
  if (waitpid (child, &status, 0) != child)
    return 2;
  printf ("Child exit status: %#x\n", status);
  return WIFEXITED (status) ? WEXITSTATUS (status) : 1;
}
