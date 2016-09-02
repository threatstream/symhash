#!/usr/bin/env python

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

import magic
import logging
from hashlib import md5
log = logging.getLogger(__name__)

def create_stub_hash(filename):
    ''' create the stub hash '''
    with open(filename, 'rb') as f:
        filedata = open(filename, 'rb').read()
        f.close()
    with magic.Magic() as m:
        filetype = m.id_filename(filename)

    if 'Mach-O' not in filetype:
        log.error('symhash only operates on Mach-O Executable files')

    try:
        from machoinfo import MachOEntity, MachOParser, MachOParserError
    except:
        log.error('machoinfo is required - if installation did not work, retreive machoinfo.py from https://raw.githubusercontent.com/crits/crits_services/master/machoinfo_service/machoinfo.py')
    macho_parser = MachOParser(filedata)
    try:
        macho_parser.parse()
    except MachOParserError, e:
        log.error("Error %s", e)
        return None
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
