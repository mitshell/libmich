from distutils.core import setup

setup(name="libmich",
      author="Benoit Michau",
      author_email="michau.benoit@gmail.com",
      url="http://michau.benoit.free.fr/codes/libmich/",
      description="A library to manipulate various data formats and network protocols",
      version="0.2.1",
      license="GPLv2",
      packages=["libmich", "libmich.core", "libmich.formats", "libmich.utils"])
