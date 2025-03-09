import os
import clang.cindex


def set_libclang_path():
    libclang_path = os.environ.get('LIBCLANG_PATH')

    if libclang_path:
        if not os.path.exists(libclang_path):
            raise ValueError(f"libclang path {libclang_path} does not exist")
        clang.cindex.Config.set_library_file(libclang_path)
