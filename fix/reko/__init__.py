import re


def fix(content):
    content = re.sub(r'(\d+)F\b', r'\1', content)
    content = re.sub(r'\(\*\s*(\w+)\)', r'* \1', content)
    content = re.sub(r'(\w+)\[\]', r'\1', content)
    content = re.sub(r'\.u0', '', content)

    content = re.sub('fn[0-9a-fA-F]+', 'func0', content, count=1)

    return content
