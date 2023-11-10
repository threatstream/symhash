#!/usr/bin/env python

from setuptools import setup

setup(
    name='symhash',
    version='0.0.3',
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
        'python-magic>=0.4.27',
        'python-magic-bin>=0.4.14',
        'future>=0.18.2',
        'ssdeep>=3.4',
    ],
    description='Anomali Symhash',
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: POSIX',
        'Programming Language :: Other Scripting Engines',
        'Programming Language :: Python :: 3.6',
    ]
)
