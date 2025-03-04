#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef __int128_t int128_t;

int SubV(int a, int b)
{
    return a - b;
}

int CmpF(unsigned int a, unsigned int b)
{
    return a < b ? -1 : (a > b ? 1 : 0);
}

float DivV(float numerator, float denominator)
{
    return numerator / denominator;
}

typedef enum
{
    Iend_LE,
    Iend_BE
} endness_t;

uint64_t Load(void *addr, size_t size, endness_t endness)
{
    uint64_t value = 0;

    memcpy(&value, addr, size);

    if ((endness == Iend_LE && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||
        (endness == Iend_BE && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    {
        uint8_t *ptr = (uint8_t *)&value;
        for (size_t i = 0; i < size / 2; i++)
        {
            uint8_t temp = ptr[i];
            ptr[i] = ptr[size - 1 - i];
            ptr[size - 1 - i] = temp;
        }
    }

    return value;
}

__uint128_t Conv(uint64_t value)
{
    return (__uint128_t)value;
}

__uint128_t Conv128to64(__uint128_t value)
{
    return (uint64_t)value;
}