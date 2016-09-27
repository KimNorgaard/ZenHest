#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

from zenhest import __version__

setup(name='zenhest',
      version=__version__,
      description='Text based event console for Zenoss',
      url='https://github.com/KimNorgaard/ZenHest',
      author=u'Kim Nørgaard',
      keywords='zenoss monitoring console',
      author_email='jasen@jasen.dk',
      license="MIT",
      install_requires=['clipboard >= 0.0.4', 'keyring >= 9.3.1', 'urwid'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 2.7',
          'Topic :: System :: Systems Administration',
          'Topic :: System :: Monitoring',
          'Topic :: Utilities',
      ],
      packages=['zenhest'],
      scripts=['bin/zenhest'],
)
