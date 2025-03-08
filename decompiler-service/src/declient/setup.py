from setuptools import setup, find_packages

setup(
    name='pydeclient',
    version='1.1.0',
    packages=find_packages(),
    include_package_data=True,
    description='A package for requesting decompilebench service',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='hustcw',
    license='MIT',
    keywords='decompiler, binary, reverse engineering',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        'aiohttp',
        'requests',
        'tqdm'
    ]
)
