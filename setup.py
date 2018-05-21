from setuptools import setup

setup(
    name="stsauth",
    version='0.1.0',
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
        'awscli',
        'boto3',
        'Click',
        'configparser',
        'requests',
        'requests_ntlm',
        'bs4'
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
