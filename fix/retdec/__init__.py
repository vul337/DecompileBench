# %%

import re

goto_pattern = re.compile(r'goto lab_0x([0-9a-f]+);')
available_label_pattern = re.compile(r'lab_0x([0-9a-f]+):')
bb_pattern = re.compile(r'// 0x([0-9a-f]+)')


def fix(content):
    all_needed_labels = goto_pattern.findall(content)
    all_target_labels = available_label_pattern.findall(content)
    bb_start = bb_pattern.findall(content)

    not_present_label = set(all_needed_labels) - set(all_target_labels)

    for x in not_present_label:
        if x in bb_start:
            content = content.replace(f'// 0x{x}', f'lab_0x{x}:// 0x{x}')

    return content


# %%
if __name__ == '__main__':
    a = '''
int64_t function_11c9(int64_t * a1, int64_t a2, int64_t * a3) {
    int32_t nmemb = a2;
    int64_t mem = (int64_t)malloc(4 * nmemb); // 0x11ef
    int64_t * mem2 = calloc(nmemb, 4); // 0x11ff
    int64_t * mem3 = calloc(nmemb, 4); // 0x120f
    if (nmemb < 1) {
        // 0x1255
        *(int32_t *)a3 = (int32_t)0;
        free(mem2);
        free(mem3);
        return mem;
    }
    int64_t v1 = (int64_t)a1;
    int64_t v2 = (int64_t)mem2; // 0x11ff
    int64_t v3 = (int64_t)mem3; // 0x120f
    int64_t v4 = v1 + 4 + (4 * a2 + 0x3fffffffc & 0x3fffffffc); // 0x1223
    int64_t v5 = v3 + 4; // 0x1238
    int64_t v6 = v1; // 0x123c
    int64_t v7 = 0;
    int64_t v8 = 0;
    int32_t v9 = *(int32_t *)v6; // 0x12bb
    int64_t v10; // 0x11c9
    int64_t v11; // 0x11c9
    int64_t v12; // 0x11c9
    int64_t v13; // 0x11c9
    int64_t v14; // 0x12ca
    int64_t v15; // 0x12e7
    int64_t v16; // 0x12d2
    int64_t v17; // 0x12ef
    if ((int32_t)v8 < 1) {
        if ((int32_t)v7 < 1) {
            // 0x12f8
            *(int32_t *)((0x100000000 * v7 >> 30) + v2) = v9;
            v10 = v8;
            v11 = v7 + 1 & 0xffffffff;
        } else {
            // 0x12e0
            v15 = v2 + 4 + (4 * v7 + 0x3fffffffc & 0x3fffffffc);
            v17 = v2;
            v13 = v17;
            while (*(int32_t *)v13 != v9) {
                // 0x12ef
                v17 = v13 + 4;
                if (v17 == v15) {
                    goto lab_0x12f8;
                }
                v13 = v17;
            }
            // 0x12a8
            *(int32_t *)((0x100000000 * v8 >> 30) + v3) = v9;
            v10 = v8 + 1 & 0xffffffff;
            v11 = v7;
        }
    } else {
        // 0x12c3
        v14 = (4 * v8 + 0x3fffffffc & 0x3fffffffc) + v5;
        v12 = v3;
        v10 = v8;
        v11 = v7;
        while (*(int32_t *)v12 != v9) {
            // 0x12d2
            v16 = v12 + 4;
            if (v16 == v14) {
                goto lab_0x12db;
            }
            v12 = v16;
            v10 = v8;
            v11 = v7;
        }
    }
    int64_t v18 = v10;
    v6 += 4;
    while (v6 != v4) {
        // 0x12bb
        v7 = v11;
        v8 = v18;
        v9 = *(int32_t *)v6;
        if ((int32_t)v8 < 1) {
            if ((int32_t)v7 < 1) {
                // 0x12f8
                *(int32_t *)((0x100000000 * v7 >> 30) + v2) = v9;
                v10 = v8;
                v11 = v7 + 1 & 0xffffffff;
            } else {
                // 0x12e0
                v15 = v2 + 4 + (4 * v7 + 0x3fffffffc & 0x3fffffffc);
                v17 = v2;
                v13 = v17;
                while (*(int32_t *)v13 != v9) {
                    // 0x12ef
                    v17 = v13 + 4;
                    if (v17 == v15) {
                        goto lab_0x12f8;
                    }
                    v13 = v17;
                }
                // 0x12a8
                *(int32_t *)((0x100000000 * v8 >> 30) + v3) = v9;
                v10 = v8 + 1 & 0xffffffff;
                v11 = v7;
            }
        } else {
            // 0x12c3
            v14 = (4 * v8 + 0x3fffffffc & 0x3fffffffc) + v5;
            v12 = v3;
            v10 = v8;
            v11 = v7;
            while (*(int32_t *)v12 != v9) {
                // 0x12d2
                v16 = v12 + 4;
                if (v16 == v14) {
                    goto lab_0x12db;
                }
                v12 = v16;
                v10 = v8;
                v11 = v7;
            }
        }
        // 0x12b2
        v18 = v10;
        v6 += 4;
    }
    int64_t v19 = v1; // 0x124d
    int64_t v20 = 0;
    int32_t v21 = *(int32_t *)v19; // 0x128f
    int64_t v22; // 0x11c9
    int64_t v23; // 0x11c9
    int64_t v24; // 0x129d
    if ((int32_t)v18 < 1) {
        // 0x127b
        *(int32_t *)((0x100000000 * v20 >> 30) + mem) = v21;
        v22 = v20 + 1 & 0xffffffff;
    } else {
        v23 = v3;
        v22 = v20;
        while (*(int32_t *)v23 != v21) {
            // 0x129d
            v24 = v23 + 4;
            if ((4 * v18 + 0x3fffffffc & 0x3fffffffc) + v5 == v24) {
                goto lab_0x127b;
            }
            v23 = v24;
            v22 = v20;
        }
    }
    int64_t v25 = v22;
    v19 += 4;
    while (v19 != v4) {
        // 0x128f
        v20 = v25;
        v21 = *(int32_t *)v19;
        if ((int32_t)v18 < 1) {
            // 0x127b
            *(int32_t *)((0x100000000 * v20 >> 30) + mem) = v21;
            v22 = v20 + 1 & 0xffffffff;
        } else {
            v23 = v3;
            v22 = v20;
            while (*(int32_t *)v23 != v21) {
                // 0x129d
                v24 = v23 + 4;
                if ((4 * v18 + 0x3fffffffc & 0x3fffffffc) + v5 == v24) {
                    goto lab_0x127b;
                }
                v23 = v24;
                v22 = v20;
            }
        }
        // 0x1286
        v25 = v22;
        v19 += 4;
    }
    // 0x1255
    *(int32_t *)a3 = (int32_t)v25;
    free(mem2);
    free(mem3);
    return mem;
}'''

    d = fix(a)
