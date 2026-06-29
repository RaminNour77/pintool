#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef BUFSIZE
#define BUFSIZE 128
#endif

#include <sys/prctl.h>

__attribute__((constructor))
static void set_dumpable() {
  prctl(PR_SET_DUMPABLE, 1);
}

int read_integer(char *format) {
  /* reads a string with new line and convert that to an integer */
  char buf[64];
  int ret;
  // no buffer overflow, 63 < 64!
  fgets(buf, 63, stdin);
  sscanf(buf, format, &ret);
  return ret;
}

static inline void _memcpy(void *dest, void *src, size_t n)
{
char *csrc = (char *) src;
char *cdest = (char *) dest;

// Copy contents of src[] to dest[]
for (int i=0; i<n; i++)
    cdest[i] = csrc[i];
}

int read_random() {
  int fd = open("/dev/urandom", O_RDONLY);
  int ret;
  if(fd < 0) {
    printf("Error on opening random\n");
    exit(-1);
  }
  read(fd, &ret, 4);
  return ret;
}

int global_random = 0;

int input_func() {
  char buf[BUFSIZE];
  size_t read_size;
  int *ptr;

  char name[1024];
  printf("Please type your name first: \n");
  // only reads 1023 chars at max
  read(0, name, 1023);
  printf("Hello ");
  printf(name);
  printf("\n");

  puts("This function will read your input for N bytes and then write them to an address A.");

  // read N
  puts("How many bytes do you want to write (N, in decimal, max 128 bytes)?");
  read_size = read_integer("%lu");
  if(read_size > BUFSIZE) {
    read_size = BUFSIZE;
  }

  // read A
  puts("What is the address that you want to write (A, in hexadexmial, e.g., 0xffffde01)?");
  ptr = (int*) read_integer("%lx");

  // read your input (arbitrary write!)
  printf("Please provide your input (MAX %d bytes)\n", read_size);
  size_t read_bytes = read(0, buf, read_size);
  _memcpy(ptr, buf, read_size);

  printf("Welcome %s!\n", name);

  return 0;
}

int main(int argc, char** argv, char** envp) {
  // Inherit EGID here..
  setregid(getegid(), getegid());
  input_func();
  return 0;
}
