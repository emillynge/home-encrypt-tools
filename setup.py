#!/usr/bin/env python

from setuptools import setup

setup(name='home-encrypt-tools',
      version='1.0',
      description='Tools for encrypting home directories on linux machines',
      author_email='emillynge24@gmail.com',
      url='https://github.com/emillynge/home-encrypt-tools',
      py_modules=['adduserencrypt'],
      entry_points={'console_scripts': ['adduser-encrypt = adduserencrypt:main']}
     )