
def fix(content):

    content = 'int __global_in_FS_OFFSET[0x100];\n' + content

    content = content.replace(
        'long in_FS_OFFSET;', 'long in_FS_OFFSET = (long)__global_in_FS_OFFSET;')

    return content
