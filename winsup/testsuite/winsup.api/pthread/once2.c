/* Test signal delivery after a pthread_once initializer handles a signal. */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t seen;

static void
handler (int signo)
{
  if (signo == SIGUSR1)
    {
      seen |= 1;
      assert (raise (SIGUSR2) == 0);
    }
  else if (signo == SIGUSR2)
    seen |= 2;
  else if (signo == SIGALRM)
    seen |= 4;
}

static void
initialize (void)
{
  assert (raise (SIGUSR1) == 0);
}

int
main (void)
{
  struct sigaction action = {0};
  stack_t stack = {0};
  stack.ss_sp = malloc (SIGSTKSZ);
  stack.ss_size = SIGSTKSZ;
  assert (stack.ss_sp != NULL);
  assert (sigaltstack (&stack, NULL) == 0);

  action.sa_handler = handler;
  assert (sigemptyset (&action.sa_mask) == 0);
  assert (sigaction (SIGUSR2, &action, NULL) == 0);
  assert (sigaction (SIGALRM, &action, NULL) == 0);

  for (int onstack = 0; onstack < 2; ++onstack)
    {
      pthread_once_t once = PTHREAD_ONCE_INIT;
      action.sa_flags = onstack ? SA_ONSTACK : 0;
      assert (sigaction (SIGUSR1, &action, NULL) == 0);
      seen = 0;
      assert (raise (SIGUSR1) == 0);
      assert (seen == 3);
      seen = 0;
      assert (pthread_once (&once, initialize) == 0);
      assert (seen == 3);

      struct timespec before, after;
      assert (clock_gettime (CLOCK_MONOTONIC, &before) == 0);
      alarm (1);
      int ret = poll (NULL, 0, 5000);
      int error = errno;
      assert (clock_gettime (CLOCK_MONOTONIC, &after) == 0);
      long elapsed_ms = (after.tv_sec - before.tv_sec) * 1000
			+ (after.tv_nsec - before.tv_nsec) / 1000000;
      if (ret != -1 || error != EINTR || elapsed_ms >= 4000)
	{
	  fprintf (stderr,
		   "poll after pthread_once returned %d, errno %d in %ld ms"
		   " (expected -1/EINTR within 4000 ms)\n",
		   ret, error, elapsed_ms);
	  return 1;
	}
      assert (seen == 7);
    }

  /* Exercise asynchronous delivery while running outside a runtime call. */
  struct timespec before, after;
  seen = 0;
  assert (clock_gettime (CLOCK_MONOTONIC, &before) == 0);
  alarm (1);
  for (;;)
    {
      for (unsigned spin = 0; spin < 1000000 && !(seen & 4); ++spin)
	;
      assert (clock_gettime (CLOCK_MONOTONIC, &after) == 0);
      if ((seen & 4) || after.tv_sec - before.tv_sec >= 4)
	break;
    }
  assert (seen == 4);

  stack.ss_flags = SS_DISABLE;
  assert (sigaltstack (&stack, NULL) == 0);
  free (stack.ss_sp);
  return 0;
}
