#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "ioctl_commands.h"

int main() {
  printf("menu\n");
  int fd = open("/proc/protocol_stat", O_RDONLY);
  printf("Enter one of following number to execute  corresponding command\n");
  printf("1-Reset Time stat\n");
  printf("2-Reset Protocol stat\n");
  printf("3-Reset IP stat\n");
  printf("4-Reset Port stat\n");
  int n ;
  char output[50];
  scanf("%d", &n);
  switch (n) {
    case 1:
      ioctl(fd, IOCTL_RESET_TIME_STAT, output);
      printf("time statisitcs is reset now!\n");
      break;
    case 2:
      ioctl(fd, IOCTL_RESET_PROTOCOL_STAT, output);
      printf("protocol statisitcs is reset now!\n");
      break;
    case 3:
      ioctl(fd, IOCTL_RESET_IP_STAT, output);
      printf("ip statisitcs is reset now!\n");
      break;
    case 4:
      ioctl(fd, IOCTL_RESET_PORT_STAT, output);
      printf("port statisitcs is reset now!\n");
      break;
    default:
      printf("please Enter only one of the above number!\n");
      break;
  }
  close(fd);
  return 0;
}
