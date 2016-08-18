#!/usr/bin/env python
'''
*************************************************************************
*
* Anomali CONFIDENTIAL
* __________________
*
*  Copyright 2016 Anomali Inc.
*  All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of Anomali Incorporated and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Anomali Incorporated
* and its suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Anomali Incorporated.
*
*************************************************************************
'''

#
# Mach-O symbol table hasher
#
# This is a Mach-O version of imphash
#
# imphash walks the import table
# creates a list of strings of form:
#   ('%s.%s', libname.lower(), funcname.lower())
#
# symhash walks the symbol table (read: loaded API calls)
# creates a list and hashes those

import os
import magic
import logging
import argparse
from hashlib import md5

logging.basicConfig(
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO)
logging.getLogger('request').setLevel(logging.WARNING)
log = logging.getLogger(__name__)


def create_stub_hash(filename):
    ''' create the stub hash '''
    with open(filename, 'rb') as f:
        filedata = open(filename, 'rb').read()
        f.close()
    with magic.Magic() as m:
        filetype = m.id_filename(filename)

    if 'Mach-O' not in filetype:
        print('symhash only operates on Mach-O Executable files')

    try:
        from machoinfo import MachOEntity, MachOParser, MachOParserError
    except:
        print 'machoinfo is required - if installation did not work, \
            retreive machoinfo.py from github.com/crits/crits_services'
    macho_parser = MachOParser(filedata)
    try:
        macho_parser.parse()
    except MachOParserError, e:
        print "Error %s" % e
        sys.exit()
    sym_list = []
    for entity in macho_parser.entities:
        for cmd in entity.cmdlist:
            if cmd['cmd'] == MachOEntity.LC_SYMTAB:
                for sym in cmd['symbols']:
                    if not sym['is_stab']:
                        if sym['n_type'] == '0x00':
                            sym_list.append(sym.get('string', ''))

    symhash = md5(','.join(sorted(sym_list))).hexdigest()

    return symhash


def main():
    opt = argparse.ArgumentParser(description='SymHash: a program to create \
        symbol table hashes and compare Mach-O executable similarity')
    opt.add_argument(
        '-f', '--file', help='The file to create a SymHash from', required=True
        )
    opt.add_argument(
        '-v', '--verbose', help='Verbose output', required=False,
        action='store_true'
        )

    options = opt.parse_args()
    f_name = options.file

    symhash = create_stub_hash(f_name)
    if options.verbose == True:
        print ('StubHash: %s' % symhash)
    else:
        print(symhash)

if __name__ == '__main__':
    main()
