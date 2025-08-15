#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<time.h>


int main() {
	int arr[6];
	arr[0] = 121;
	arr[1] = 1231231;
	arr[2] = 20312312;
	arr[3] = 122342342;
	arr[4] = 90988878;
	arr[5] = 4294967266;

	int sum = 0;
	srand(time(NULL));

	for(int i = 0; i <= 5; ++i) {
		uint32_t r = rand();
		arr[i] -= r%10 - 1;
	}

	for(int i = 0; i <= 5; ++i) {
		sum += arr[i];
	}

	printf("%d\n", sum);
	return 0;
}
