/*
 ============================================================================
 Name        : example.c
 Author      : Henryk Plötz <henryk@ploetzli.ch>
 Version     :
 Copyright   : (c) 2015 Henryk Plötz
 Description : Uses shared library to print greeting
               To run the resulting executable the LD_LIBRARY_PATH must be
               set to ${project_loc}/libtrsa/.libs
               Alternatively, libtool creates a wrapper shell script in the
               build directory of this program which can be used to run it.
               Here the script will be called example.
 ============================================================================
 */

#include "libtrsa.h"

int main(void) {
  print_hello();
  return 0;
}
