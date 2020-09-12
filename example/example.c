#include "remap.h"
#include <stdio.h>
#include <errno.h>

int main() {
  int res = remap_process_binary(main);
  printf("remap result: %d, errno: %d\n", res, (int)errno);
  return 0;
}
