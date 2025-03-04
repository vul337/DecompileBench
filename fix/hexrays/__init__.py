
import re


def fix(content):
    content = re.sub(
        r'\b\w+@<[^>]+>',
        lambda m: m.group().split('@')[0], content
    )

    content = re.sub('sub_[0-9a-fA-F]+', 'func0', content, count=1)

    return content
