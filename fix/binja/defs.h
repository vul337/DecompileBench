#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <mmintrin.h>  //MMX
#include <xmmintrin.h> //SSE(include mmintrin.h)
#include <emmintrin.h> //SSE2(include xmmintrin.h)
#include <pmmintrin.h> //SSE3(include emmintrin.h)
#include <tmmintrin.h> //SSSE3(include pmmintrin.h)
#include <smmintrin.h> //SSE4.1(include tmmintrin.h)
#include <nmmintrin.h> //SSE4.2(include smmintrin.h)
#include <wmmintrin.h> //AES(include nmmintrin.h)
#include <immintrin.h> //AVX(include wmmintrin.h)
// #include <intrin.h>  //(include immintrin.h)

typedef float ufloat;

#define __andpd_xmmxuq_memxuq _mm_and_pd;
#define __andps_xmmxuq_memxuq _mm_and_ps;
#define __andpd_xmmxud_memxud _mm_and_pd;
#define __andps_xmmxud_memxud _mm_and_ps;

void __stack_chk_fail(void)
{
    printf("Stack smashing detected\n");
    exit(-1);
}

char TEST_BITQ(uint64_t a, uint64_t b)
{
    return (a & b) == b;
}

char FCMP_O(float a, float b)
{
    return a < b;
}
char FCMP_UO(float a, float b)
{
    return a > b;
}

int32_t HIGHD(int32_t x)
{
    return (x >> 16) & 0xFFFF;
}

int32_t LOWD(int32_t x)
{
    return x & 0xFFFF;
}

int32_t COMBINE(int32_t high, int32_t low)
{
    return (high << 16) | (low & 0xFFFF);
}

int32_t HIGHQ(int64_t value)
{
    return (int32_t)(value >> 32);
}

int32_t LOWQ(int64_t value)
{
    return (int32_t)value;
}

uint64_t ROLQ(uint64_t value, int count)
{
    const uint nbits = sizeof(uint64_t) * 8;

    if (count > 0)
    {
        count %= nbits;
        uint64_t high = value >> (nbits - count);
        if ((uint64_t)(-1) < 0) // signed value
            high &= ~(((uint64_t)(-1) << count));
        value <<= count;
        value |= high;
    }
    else
    {
        count = -count % nbits;
        uint64_t low = value << (nbits - count);
        value >>= count;
        value |= low;
    }
    return value;
}
