try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


install_requires = [
    "tornado"
]

setup(name="ustudio-hmac-tornado",
      version="0.1.1",
      description="Simple HMAC Client/Server authentication for Tornado",
      url="https://github.com/ustudio/ustudio-hmac-tornado",
      packages=["hmacauth", "hmacauth.client", "hmacauth.server"],
      install_requires=install_requires)
