#!/usr/bin/env python

from setuptools import setup

setup(
    name='symhash',
    version='0.0.2',
    url='https://github.com/threatstream/symhash',
    author='Aaron Shelmire',
    author_email='aaron.shelmire@anomali.com',
    license='GNU GPLv3',
    packages=[
        'symhash',
    ],
    scripts=[
        'bin/symhash'
    ],
    install_requires=[
        'filemagic==1.6',
        'future==0.18.3',
    ],
    description='Anomali Symhash',
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX',
        'Programming Language :: Other Scripting Engines',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ]
)
