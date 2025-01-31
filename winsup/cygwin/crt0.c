/* crt0.c

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winlean.h"
#include <sys/cygwin.h>

extern int main (int argc, char **argv);

#ifdef __MSYS__
void msys_crt0 (int (*main) (int, char **));
#else
void cygwin_crt0 (int (*main) (int, char **));
#endif

void
mainCRTStartup ()
{
#ifdef __MSYS__
  msys_crt0 (main);
#else
  cygwin_crt0 (main);
#endif

  /* These are never actually called.  They are just here to force the inclusion
     of things like -lbinmode.  */

  cygwin_premain0 (0, NULL, NULL);
  cygwin_premain1 (0, NULL, NULL);
  cygwin_premain2 (0, NULL, NULL);
  cygwin_premain3 (0, NULL, NULL);
}

void WinMainCRTStartup(void) __attribute__ ((alias("mainCRTStartup")));
