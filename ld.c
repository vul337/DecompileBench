#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#pragma clang attribute push(__attribute__((no_instrument_function)), apply_to = function)

typedef struct
{
    unsigned long addr1;
    unsigned long addr2;
} FixupPair;

typedef struct
{
    unsigned long self_base;
    unsigned long lib_base;
} BaseAddresses;

static const char *config_path;
__attribute__((constructor)) static void init_config_path(void)
{
    config_path = getenv("MAPPING_TXT");
    if (!config_path)
    {
        config_path = "address_mapping.txt";
    }
}

__attribute__((no_instrument_function))
FixupPair *
read_fixup_pairs(int *count)
{
    FILE *fp = fopen(config_path, "r");
    if (!fp)
    {
        perror("Failed to open config");
        return NULL;
    }

    int lines = 0;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        lines++;
    }

    rewind(fp);

    FixupPair *pairs = (FixupPair *)malloc(lines * sizeof(FixupPair));
    if (!pairs)
    {
        perror("Memory allocation failed");
        fclose(fp);
        return NULL;
    }

    if (fgets(buffer, sizeof(buffer), fp) == NULL)
    {
        fprintf(stderr, "Failed to read binary name from config");
        fclose(fp);
        return NULL;
    }

    int read_lines = 0;

    for (int i = 0; i < lines; i++)
    {
        if (fgets(buffer, sizeof(buffer), fp) == NULL)
        {
            break;
        }

        read_lines++;

        if (sscanf(buffer, "0x%lx 0x%lx", &pairs[i].addr1, &pairs[i].addr2) != 2)
        {
            fprintf(stderr, "Invalid format in line %d\n", i + 1);
            free(pairs);
            fclose(fp);
            return NULL;
        }
    }

    fclose(fp);
    *count = read_lines;
    return pairs;
}

__attribute__((no_instrument_function))
BaseAddresses
get_base_addresses()
{
    BaseAddresses bases = {0, 0};

    FILE *fixup_fp = fopen(config_path, "r");
    if (!fixup_fp)
    {
        perror("Failed to open config");
        return bases;
    }

    char binary_name[256] = {0};
    if (fgets(binary_name, sizeof(binary_name), fixup_fp) == NULL)
    {
        perror("Failed to read binary name from config");
        fclose(fixup_fp);
        return bases;
    }
    fclose(fixup_fp);

    binary_name[strcspn(binary_name, "\r\n")] = 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp)
    {
        perror("Failed to open /proc/self/maps");
        return bases;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        unsigned long start;
        char permissions[5];
        char path[256] = {0};

        sscanf(buffer, "%lx-%*x %4s %*s %*s %*s %255s", &start, permissions, path);

        if (strstr(path, binary_name) || strlen(path) == 0)
        {
            if (bases.self_base == 0 && start != 0xbabe0000)
            {
                bases.self_base = start;
            }
        }
        else if (strstr(path, "libfunction.so"))
        {
            if (bases.lib_base == 0)
            {
                bases.lib_base = start;
            }
        }

        if (bases.self_base != 0 && bases.lib_base != 0)
        {
            break;
        }
    }

    fclose(fp);
    return bases;
}

__attribute__((no_instrument_function))
__attribute__((constructor)) void
fixup()
{
    init_config_path();
    int count = 0;
    FixupPair *pairs = read_fixup_pairs(&count);

    if (!pairs)
    {
        fprintf(stderr, "Failed to read fixup pairs\n");
        return;
    }

    BaseAddresses bases = get_base_addresses();

    if (bases.self_base == 0 || bases.lib_base == 0)
    {
        return;
    }
    else
    {
        for (int i = 0; i < count; i++)
        {
            u_int64_t base_binary_addr = (u_int64_t)(pairs[i].addr1 + bases.self_base);
            u_int64_t libfunction_addr = (u_int64_t)(pairs[i].addr2 + bases.lib_base);
            *(u_int64_t *)libfunction_addr = base_binary_addr;
        }
    }

    free(pairs);
}

#pragma clang attribute pop
