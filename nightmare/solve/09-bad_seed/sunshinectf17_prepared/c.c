#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<time.h>

int main() {

	srand(time(0));
	for(int i = 0; i <= 49; ++i)
		printf("%d\n", rand()%100);

	return 0;
}
