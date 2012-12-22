#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<string.h>

int main()
{
    int fd;
    char buffer[80];

    fd = open("/mnt/mpt_wrapfs/a.txt",O_CREAT|O_RDWR, S_IREAD|S_IWRITE);
    if (fd != -1)
    {
    printf("a.txt opened for read/write access\n");
    lseek(fd, 0L, 0); 
    if (write(fd, "Writing this to the file", 20))
    {
    	printf("data written to a.txt\n");
    }
    close (fd);
    }
    exit (0);
}
