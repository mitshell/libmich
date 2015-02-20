# −*− coding: UTF−8 −*−
# pre install script to compile ASN.1 modules

def main():
    print('[install] compiling ASN.1 modules... be patient')
    from libmich.asn1.processor import generate_modules, MODULES
    generate_modules(MODULES)
    print('[install] compiling ASN.1 modules... done')

if __name__ == '__main__':
    main()

