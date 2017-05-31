try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages


install_requires = [
    "tornado"
]

setup(name="ustudio-hmac-tornado",
      version="0.2.0",
      description="Simple HMAC Client/Server authentication for Tornado",
      url="https://github.com/ustudio/ustudio-hmac-tornado",
      packages=find_packages(exclude=["tests", "dist"]),
      install_requires=install_requires)
