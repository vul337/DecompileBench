
import re


def fix(content,function_name):
    content = re.sub(
        r'\b\w+@<[^>]+>',
        lambda m: m.group().split('@')[0], content
    )

    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)
    content = re.sub(r'#include\s*<[^>]+>', '', content)

    #function declaration
    declaration_pattern = re.compile(r'^[ \t]*(?:[a-zA-Z_][\w\s\*\(\)]*)\s+[a-zA-Z_]\w*\s*\([^;]*\);\s*$')

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

