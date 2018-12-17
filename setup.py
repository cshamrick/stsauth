import os
from setuptools import setup


def get_requirements(env=''):
    path = os.path.dirname(os.path.abspath(__file__))
    fn = 'requirements{}{}.txt'.format(('-' if env else ''), env)
    with open(os.path.join(path, fn)) as fp:
        return [x.strip() for x in fp.read().split('\n') if not x.startswith('#')]


with open('README.md', 'r') as fh:
    long_description = fh.read()

install_requires = get_requirements()
tests_require = get_requirements('test')

setup(
    name='stsauth',
    version='0.3.0',
    author='Scott Hamrick',
    author_email='scott@scotthamrick.com',
    description='CLI tool for fetching AWS tokens.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/cshamrick/stsauth',
    py_modules=['stsauth', 'cli'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Operating System :: OS Independent',
    ],
    install_requires=install_requires,
    tests_require=tests_require,
    entry_points='''
        [console_scripts]
        stsauth=cli:cli
    ''',
    license='MIT',
)
