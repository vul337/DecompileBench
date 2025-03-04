#include <assert.h>
#include <stdio.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int word32;
typedef long long word64;
typedef unsigned int uword32;
typedef unsigned int uint32;
typedef short word16;
typedef unsigned short uword16;
typedef float real32;
typedef unsigned long long uint64;
typedef int int32;
typedef long long int64;
typedef int Eq_83;
typedef char byte;
typedef char Eq_80;
#define null 0
typedef int *ptr64;

typedef struct
{
    int64_t high;
    int64_t low;
} word128;

word128 SEQ(int64_t high, uint64_t low)
{
    word128 result;
    result.high = high;
    result.low = low;
    return result;
}

int64_t CONVERT(int32_t value, word32 param1, int64_t param2)
{
    return (int64_t)value;
}