
from setuptools import setup, find_packages

version = '0.1'
classifiers = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 3',
    'Topic :: Software Development :: Libraries',
]


setup(name='python-bitcoinlib',
      version=version,
      description='Bitcoin library',
      long_description=open("README").read(),
      keywords='bitcoin protocol',
      author='Jeff Garzik',
      author_email='jgarzik@bitpay.com',
      url='https://github.com/jgarzik/python-bitcoinlib',
      license='MIT (LGPL rpc.py)',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      classifiers=classifiers,
      )
