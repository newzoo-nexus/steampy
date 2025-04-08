from setuptools import setup
import sys

if not sys.version_info[0] == 3 and sys.version_info[1] < 8:
    sys.exit('Python < 3.8 is not supported')

version = '1.1.3'

setup(
    name='steampy',
    packages=['steampy', 'test', 'examples', ],
    version=version,
    description='A Steam lib for trade automation',
    author='Brian Fouts',
    author_email='brian.fouts@newzoo.com',
    license='MIT',
    url='https://github.com/newzoo-nexus/steampy',
    download_url='https://github.com/newzoo-nexus/steampy/tarball/' + version,
    keywords=['steam', 'trade', ],
    classifiers=[],
    install_requires=[
        "requests",
        "beautifulsoup4",
        "rsa"
    ],
)
