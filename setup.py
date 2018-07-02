from setuptools import setup

with open('README.md', 'r') as fh:
    long_description = fh.read()


setup(
    name='stsauth',
    version='0.2.0',
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
    install_requires=[
        'awscli>=1.15.0,<2',
        'boto3>=1.7.0,<2',
        'beautifulsoup4>=4.6.0,<5',
        'Click>=6.7,<7',
        'click-log>=0.2.1,<0.3',
        'configparser>=3.5.0,<4',
        'requests>=2.18.0,<3',
        'requests_ntlm>=1.1.0,<2',
    ],
    entry_points='''
        [console_scripts]
        stsauth=cli:cli
    ''',
    license='MIT',
)
