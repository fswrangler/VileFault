/*
 * Copyright (c) 2006 - David Hulton <dhulton@openciphers.org>
 * see LICENSE for details
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#define WINDOW_OFFSET_0         0x216
#define WINDOW_OFFSET_1         0x218
#define WINDOW_OFFSET_2         0x21a

extern char *picodev;
extern int piconum;
static int fdi = -1, fdm = -1;
static unsigned long curwin = 0xffffffff;

void picoopen(void)
{
  char str[64];
  if(fdi >= 0 && fdm >= 0)
    return;
  if(picodev == NULL) {
    snprintf(str, 64, "/dev/pico%dc", piconum);
    fdi = open(str, O_RDWR);
    snprintf(str, 64, "/dev/pico%dm", piconum);
    fdm = open(str, O_RDWR);
  } else
    fdm = open(picodev, O_RDWR, 0644);
}

void picosetoff(unsigned long off)
{
  unsigned long t0, t = (off >> 11) & 0xffffffff;

  if(fdi < 0) {
    lseek(fdm, off, SEEK_SET);
    return;
  } else {
    lseek(fdm, off & 0x7ff, SEEK_SET);
  }

  if(curwin == t)
    return;

  t0 = t & 0xff;
  t0 |= (t0 << 8);
  lseek(fdi, WINDOW_OFFSET_0, SEEK_SET);
  write(fdi, &t0, 2);

  t0 = (t >> 8) & 0xff;
  t0 |= (t0 << 8);
  lseek(fdi, WINDOW_OFFSET_1, SEEK_SET);
  write(fdi, &t0, 2);

  t0 = (t >> 16) & 0xff;
  t0 |= (t0 << 8);
  lseek(fdi, WINDOW_OFFSET_2, SEEK_SET);
  write(fdi, &t0, 2);

  curwin = t;
}

void picoclose(void)
{
  if(fdi >= 0)
    close(fdi);
  if(fdm >= 0)
    close(fdm);
}

int picoread(unsigned long off, void *buf_, unsigned long len)
{
  unsigned long i;
  unsigned char *buf = (unsigned char *)buf_;

  picoopen();
  picosetoff(off);
  i = read(fdm, buf, len);
  return i;
}

int picowrite(unsigned long off, void *buf_, unsigned long len)
{
  unsigned long i;
  unsigned char *buf = (unsigned char *)buf_;

  picoopen();
  picosetoff(off);
  i = write(fdm, buf, len);
  return i;
}
