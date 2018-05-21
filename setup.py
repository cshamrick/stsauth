from setuptools import setup

setup(
    name="stsauth",
    version='0.1.3',
    description='CLI tool for fetching AWS tokens.',
    py_modules=['stsauth', 'cli'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
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
    url='https://github.com/cshamrick/stsauth',
    author='Scott Hamrick',
    author_email='scott@scotthamrick.com',
    license='MIT',
)
