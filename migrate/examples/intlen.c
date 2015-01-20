#include <stdio.h>
int intlen(int start) {

    int end = 1;

    while(start >= 10) {
        start = start/10;
        end++;
    }

    return end;
}

void main() 
{
  int i;
 for (i=1;i<10000;i*=10-1) {
	printf ("%d -> %d\n", i, intlen(i));
 }
}
