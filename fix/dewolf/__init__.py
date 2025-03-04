
import re


def fix(content):
    content = re.sub(r'\[\d+\]', '', content)
    content = re.sub(r'zx\.o\(0\)', '0', content)
    content = re.sub(r'\bunsigned int\b', 'int', content)
    content = re.sub(r'\bint128_t\b', 'float', content)
    content = re.sub(r'\bint512_t\b', 'float', content)

    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)

    return content
