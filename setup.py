# −*− coding: UTF−8 −*−
import os
from distutils.core import setup
from distutils.command.install import install

try:
    from preinstall import main as preinstall
except ImportError:
    preinstall = lambda: None

class my_install(install):
    def run(self):
        # ASN.1 modules compilation
        preinstall()
        #
        install.run(self)

def generate_pkg_data():
    data = ['utils/*.bmp', 'mobnet/*.db', 
            'asn1/modules/*.pck', 'asn1/modules/*.txt']
    asn_dir = os.listdir('./libmich/asn1/asn')
    for d in asn_dir:
        data.append('asn1/asn/{0}/*.asn'.format(d))
        data.append('asn1/asn/{0}/*.txt'.format(d))
    return data

setup(name="libmich",
      author="Benoit Michau",
      author_email="michau.benoit@gmail.com",
      url="http://michau.benoit.free.fr/",
      description="A library to manipulate various data formats and network protocols",
      long_description=open("README.txt", "r").read(),
      version="0.3.0",
      license="GPLv2",
      packages=["libmich", "libmich.utils", "libmich.core", "libmich.formats",
                "libmich.asn1", "libmich.mobnet"],
      package_data={"libmich":generate_pkg_data()},
      cmdclass={"install": my_install},
      )

