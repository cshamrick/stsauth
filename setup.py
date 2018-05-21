from setuptools import setup

setup(
    name="stsauth",
    version='0.1.1',
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
        'awscli==1.15.24',
        'boto3==1.7.24',
        'click==6.7',
        'configparser==3.5.0',
        'requests==2.18.4',
        'requests-ntlm==1.1.0',
        'bs4==0.0.1'
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
