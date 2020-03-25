/*
Tomasz Stachowski
309675
*/

#include "trace.h"
#include "error.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Wrong number of arguments\n");
		return EXIT_FAILURE;
	}

	trace(argv[1], 3, 30);

	return EXIT_SUCCESS;
}
