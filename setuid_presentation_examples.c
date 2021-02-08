#define _GNU_SOURCE // Gives access to some more functions (getresuid)
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void print_uid() { // Just print UIDs to see how they change
  uid_t ruid;
  uid_t euid;
  uid_t suid;
  getresuid(&ruid, &euid, &suid);
  printf("Real: %d, Effective: %d, Saved: %d\n", ruid, euid, suid);
}

void example_1() { // show suid bit works
  print_uid();
}

void example_2() { // permission lower, raise, drop and try to regain (fail)
  int ret;
  printf("Starting UIDs: \n");
  print_uid();

  // set euid to 1000

  ret = seteuid(1000);
  printf("seteuid(1000) return code: %d\n", ret);
  printf("Changed UIDs:\n");
  print_uid();

  // regain euid 0

  printf("\n\nRegain privileges: \n");
  ret = seteuid(0);
  printf("seteuid(0) return code: %d\n", ret);
  print_uid();

  // Permanently drop privileges

  printf("\n\nPermanently drop privileges: \n");
  ret = setuid(1000);
  printf("setuid(1000) return code: %d\n", ret);
  printf("Dropped privileges: \n");
  print_uid();

  // Attempt to regain them

  printf("\n\nTry to regain privileges: \n");
  ret = setuid(0);
  printf("setuid(0) return code: %d\n", ret);
  printf("UIDs unchanged: \n");
  print_uid();
}

void example_3() { // strace example
  // These are just two simple syscalls:
  setuid(1000); // Drop all privileges
  seteuid(0); // Try to regain them
  // This simple function is to make the syscalls easier to see
}

void example_4() { // append to file user data
  const char* path = getenv("PASSWORD_LOG_FILE");
	char sentence[1000];
	FILE *fptr;
	fptr = fopen(path, "a");

	while(1) {
		printf("Enter sentence to log:\n");
		fgets(sentence, sizeof(sentence), stdin);
		if ( strcmp(sentence, "QUIT\n") == 0 ) { break;}
		fprintf(fptr, "%d : %s", (int)time(NULL), sentence);
	}
	fclose(fptr);
}

void example_5() { // Misuse prevention example:
  // starting euid is 0
  int ret;
  ret = setuid(1000); // drop privileges
  if (ret != 0) { // Check syscall succeeds
    exit(ret); // exit if fail
  }
  if (setuid(0) == 0) { // check if privileges can be regained
    exit(1);
  }
  // Now safe to handle potentially malicious input
}

int main() {
  pid_t proc_num = getpid();
  printf("Proccess id: %d\n", proc_num);
  int a;
  printf("Enter example number to run: ");
  scanf("%d", &a);
  switch (a) {
    case 1:
      example_1();
      break;
    case 2:
      example_2();
      break;
    case 3:
      example_3();
      break;
    case 4:
      example_4();
      break;
    case 5:
      example_5();
      break;
  }
}
