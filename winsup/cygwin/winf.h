/* winf.h

   Copyright 2006, 2007, 2011 Red Hat, Inc.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#ifndef _WINF_H
#define _WINF_H

/* Hack for Cygwin processes.  If the Windows command line length gets slightly
   bigger than this value, the stack position is suddenly moved up by 64K for
   no apparent reason, which results in subsequent forks failing.  Since Cygwin
   processes get the full command line as argv array anyway, this only affects
   the maximum command line length of Cygwin applications which nonsensically
   have a WinMain instead of a main entry point or which use GetCommandLine. */
#define MAXCYGWINCMDLEN 30000

#define MAXWINCMDLEN 32767
#define LINE_BUF_CHUNK (MAX_PATH * 2)

class av
{
  char **argv;
  int calloced;
 public:
  int argc;
  bool win16_exe;
  av (): argv (NULL) {}
  av (int ac_in, const char * const *av_in) : calloced (0), argc (ac_in), win16_exe (false)
  {
    TRACE_IN;
    argv = (char **) cmalloc_abort (HEAP_1_ARGV, (argc + 5) * sizeof (char *));
    memcpy (argv, av_in, (argc + 1) * sizeof (char *));
  }
  void *operator new (size_t, void *p) __attribute__ ((nothrow)) {return p;}
  void set (int ac_in, const char * const *av_in) {new (this) av (ac_in, av_in);}
  ~av ()
  {
    TRACE_IN;
    if (argv)
      {
	for (int i = 0; i < calloced; i++)
	  if (argv[i])
	    cfree (argv[i]);
	if (argv)
      cfree (argv);
      }
  }
  int unshift (const char *what, int conv = 0);
  operator char **() {TRACE_IN; return argv;}
  void all_calloced () {TRACE_IN; calloced = argc;}
  void replace0_maybe (const char *arg0)
  {
    TRACE_IN; 
    /* Note: Assumes that argv array has not yet been "unshifted" */
    if (!calloced)
      {
	argv[0] = cstrdup1 (arg0);
	calloced = true;
      }
  }
  void replace (int i, const char *arg)
    {
  TRACE_IN;
      argv[i] = cstrdup1 (arg);
    }
  void dup_maybe (int i)
  {
    TRACE_IN;
    if (i >= calloced)
      argv[i] = cstrdup1 (argv[i]);
  }
  void dup_all ()
  {
    TRACE_IN;
    for (int i = calloced; i < argc; i++)
      argv[i] = cstrdup1 (argv[i]);
  }
  int fixup (const char *, path_conv&, const char *, bool);
};

class linebuf
{
 private:
  size_t bufidx;
  size_t alloced;
 public:
  char *buf;
  linebuf () : bufidx (0), alloced (0), buf (NULL) {}
  ~linebuf () {if (buf) free (buf);}
  void add (const char *, int) __attribute__ ((regparm (3)));
  void add (const char *what) {add (what, strlen (what));}
  void prepend (const char *, int);
  void finish (bool) __attribute__ ((regparm (2)));
  bool fromargv(av&, const char *, bool) __attribute__ ((regparm (3)));;
  operator char *() {return buf;}
  size_t idx() {return bufidx;}
};

#endif /*_WINF_H*/
