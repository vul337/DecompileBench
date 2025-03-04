
import re


patterns_replacements = [
    (re.compile(r'@ zmm0'), ''),
    (re.compile(r'@ zmm1'), ''),
    (re.compile(r'__pure'), ''),
    (re.compile(r'truncf\(([^,]+),\s*[^)]+\)'), r'truncf(\1)'),
    (re.compile(r'\[\s*0x[0-9a-fA-F]+\s*\]'), ''),
    (re.compile(r'(\d+)f'), r'\1'),
    (re.compile(r'nullptr'), 'NULL'),
    (re.compile(r'cond:[^ \n]+'), 'cond'),
    (re.compile(r'out\.(\d+)'), r'out_\1'),
    (re.compile(r'int128_t'), 'float'),
    (re.compile(r'int512_t'), 'float'),
]


# additional_declarations = {
#     'data_2008': 'extern char data_2008;\n',
#     'data_200c': 'const char data_200c[] = "";\n',
#     'data_2070': 'extern char data_2070;\n',
#     'data_200d': 'const char data_200d ;\n',
#     'data_2021': 'const char data_2021 ;\n'
# }


def fix(content):
    for pattern, replacement in patterns_replacements:
        content = pattern.sub(replacement, content)

    # for key, declaration in additional_declarations.items():
    #     if key in content:
    #         content = declaration + content

    content = '''
uint64_t fsbase_content[0x100];
''' + content

    content = content.replace(
        'void* fsbase;', 'uint64_t* fsbase = fsbase_content;')
    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)

    return content
