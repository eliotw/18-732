#include <stdio.h>

int main() {
	char name[] = "foo.txt";
	char text[] = "You Lose!";
	FILE *f;
	f = fopen(name, "a");
	fprintf(f, text);
	fclose(f);
}
