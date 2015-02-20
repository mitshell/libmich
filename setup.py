from distutils.core import setup
from distutils.command.install_data import install_data

class post_install(install_data):
    def run(self):
        # Call parent 
        install_data.run(self)
        # Compile ASN.1 modules
        #print('post installation: compiling ASN.1 modules')
        #from libmich.asn1.processor import *
        #generate_modules(MODULES)


setup(name="libmich",
      author="Benoit Michau",
      author_email="michau.benoit@gmail.com",
      url="http://michau.benoit.free.fr/",
      description="A library to manipulate various data formats and network protocols",
      long_description=open("README.txt", "r").read(),
      version="0.3.0",
      license="GPLv2",
      packages=["libmich", "libmich.core", "libmich.formats", "libmich.utils", "libmich.asn1", "libmich.mobnet"],
      cmdclass={'install_data':post_install})
