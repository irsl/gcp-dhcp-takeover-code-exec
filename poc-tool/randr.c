#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
/*
  srandom(0x616817db);
  long int l = random();
  printf("%08x\n", l);
*/
  if(argc != 6) {
     printf("Usage: %s ipaddress min_pid max_pid min_unixtime max_unixtime\n", argv[0]);
     return -1;
  }

  char* ipaddress_str = argv[1];
  int min_pid = atoi(argv[2]);
  int max_pid = atoi(argv[3]);
  int min_unixtime = atoi(argv[4]);
  int max_unixtime = atoi(argv[5]);
  int ipaddress = inet_addr(ipaddress_str);

  // small optimization as these ranges overlap!
  int min_add = min_pid + min_unixtime;
  int max_add = max_pid + max_unixtime;

  for(int add = min_add; add <= max_add; add++) {
     unsigned seed = ipaddress + add;
     srandom(seed);
     long int l = random();
     printf("%08x\n", l);
  }
}
