import re


def replacement(match):
    suffix = match.group(1)
    return f'field____{suffix}'


def fix(content):
    # concat_pattern = re.compile(r'\(([^()]*) CONCAT ([^()]+)\)')
    out_number_pattern = re.compile(r'\bout\.(\d+)\b')

    # content = concat_pattern.sub(r'\1', content)
    content = out_number_pattern.sub(r'out_\1', content)

    content = re.sub(r'field_-(\w+);', replacement, content)
    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)

    return content
