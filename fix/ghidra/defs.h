#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>

typedef unsigned int uint;
typedef unsigned char uint8;
typedef uint8 uint7;
typedef signed char sint8;
typedef char int8;
typedef int8 int7;
typedef short int16;
typedef signed short sint16;
typedef unsigned short uint16;
typedef int int32;
typedef signed int sint32;
typedef unsigned int uint32;

typedef int8 byte;
typedef long undefined8;
typedef int undefined4;
typedef char undefined;
typedef undefined undefined1;
typedef short undefined2;
typedef long undefined6;
typedef unsigned long ulong;
typedef unsigned int uint;
typedef int int32_t;
typedef float float32_t;
typedef unsigned long size_t;
typedef char bool;
typedef double float64_t;
typedef char gchar;
typedef long scalar_t__;
typedef long long int128_t;
#define false 0
#define true 1
size_t fARCH_aarch64;
size_t fARCH_arm;
size_t fARCH_i386;
size_t fARCH_x86_64;
scalar_t__ verbose;
int MIN_SIZE;
struct stat
{
    int st_mode;
};
int64_t __readfsqword(size_t offset);
extern void __stack_chk_fail(void) __attribute__((noreturn));

#include <mmintrin.h>  //MMX
#include <xmmintrin.h> //SSE(include mmintrin.h)
#include <emmintrin.h> //SSE2(include xmmintrin.h)
#include <pmmintrin.h> //SSE3(include emmintrin.h)
#include <tmmintrin.h> //SSSE3(include pmmintrin.h)
#include <smmintrin.h> //SSE4.1(include tmmintrin.h)
#include <nmmintrin.h> //SSE4.2(include smmintrin.h)
#include <wmmintrin.h> //AES(include nmmintrin.h)
#include <immintrin.h> //AVX(include wmmintrin.h)