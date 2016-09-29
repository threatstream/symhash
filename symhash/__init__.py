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
from hashlib import md5

from symhash.machoinfo import MachOEntity, MachOParser, MachOParserError


def create_sym_hash(filename=None, data=None):
    # create the sym hash
    if filename:
        with open(filename, 'rb') as f:
            data = f.read()

    if not data:
        return

    with magic.Magic() as m:
        filetype = m.id_buffer(data[0:1000])

    if 'Mach-O' not in filetype:
        print("Data provided is not a valid Mach-O filetype")
        return

    macho_parser = MachOParser(data)

    try:
        macho_parser.parse()
    except MachOParserError as e:
        print("Error {}".format(e))
        return

    sym_dict = {}

    for entity in macho_parser.entities:
        if entity.magic_str != 'Universal':

            entity_string = "{} {} {}".format(entity.cpu_type_str,
                                              entity.filetype_str,
                                              entity.magic_str)

            sym_list = []

            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_SYMTAB:
                    for sym in cmd['symbols']:
                        if not sym['is_stab']:
                            if sym['external'] is True:
                                if sym['n_type'] == '0x00':
                                    sym_list.append(sym.get('string', '').decode())

            symhash = md5(','.join(sorted(sym_list)).encode()).hexdigest()
            sym_dict[entity_string] = symhash

    return sym_dict
