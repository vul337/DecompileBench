# %%
import re


def fix(content,function_name):
    content = re.sub(
        r'\b\w+@<[^>]+>',
        lambda m: m.group().split('@')[0], content
    )

    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)
    content = re.sub(r'#include\s*<[^>]+>', '', content)

    #function declaration
    declaration_pattern = re.compile(r'^[ \t]*(?:[a-zA-Z_][\w\s\*\(\)]*)\s+[\*]*[a-zA-Z_]\w*\s*\([^;]*\);\s*$')

    function_name_pattern = r'(?P<function_name>[a-zA-Z_]\w*)'
    implementation_pattern = re.compile(r'^[ \t]*(?:[a-zA-Z_][\w\s\*\(\)]*)\s+' + function_name_pattern + r'\s*\([^;]*\)\s*(?!.*;).*{')


    lines = content.split('\n')
    new_lines = []
    flag = 0
    for line in lines:
        if flag==0 and declaration_pattern.match(line):
            continue
        if implementation_pattern.match(line):
            flag = 1
            function_name_catched = implementation_pattern.match(line).group('function_name')
            if function_name_catched != function_name:
                line = line.replace(function_name_catched, function_name)
        
        new_lines.append(line)
    content = '\n'.join(new_lines)

    return content

# # %%
# test = '''
# #define MAX_ERROR_MSG_SIZE 128
# #define MAX_CACHE_SIZE 4096
# #define ERROR_COMPILATION_FAILED 4294967252LL

# // External dependencies
# extern void *zend_string_concat2(const char *str1, size_t len1, const char *str2, size_t len2);
# extern void *zend_hash_find(void *hash_table, const void *key);
# extern void *zend_hash_add_new_mem(void *hash_table, const void *key, void *value);
# extern void *php_pcre2_compile(const char *pattern, size_t pattern_len, unsigned int options, unsigned int *error_code, size_t *error_offset, void *context);
# extern void *php_pcre2_maketables(void);
# extern void *make_subpats_table(unsigned int capture_count, void **context);
# extern void *estrndup(const char *str, size_t length);
# extern unsigned int *get_character_classes(void);
# '''

# a=fix(test, 'evbuffer_search_eol')
# %%
