from setuptools import setup, find_packages
import os

version = '0.1.0'

setup(name='repoze.who.plugins.facebook_connect',
      version=version,
      description="A Facebook Connect plugin for repoze.who",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        ],
      keywords='facebook connect repoze who identification authentication plugin',
      author='Martin Thorsen Ranang',
      author_email='mtr@ranang.org',
      url='http://ranang.org/docs/repoze.who.plugins.facebook_connect',
      license="BSD-derived (http://www.repoze.org/LICENSE.txt)",
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'repoze.who>=1.0.6', 
	  'facebook-python-sdk>=0.1',
          'setuptools',
          'webob',
          'zope.interface'
      ],
      test_requires=[   
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      test_suite='repoze.who.plugins.facebook_connect.tests'
      )
