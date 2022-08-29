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

import os
from hashlib import md5

import magic

from symhash.machoinfo import MachOEntity, MachOParser, MachOParserError


def get_dylib_name_by_ordinal(dylib_list, library_ordinal, basename_only = False):
    if library_ordinal > 0 and library_ordinal <= 253:
        if basename_only:
            return os.path.basename(dylib_list[library_ordinal - 1])
        else:
            return dylib_list[library_ordinal - 1]
    elif library_ordinal in (0, 254, 255):  # 0 = invalid, 254 = DYNAMIC_LOOKUP_ORDINAL, 255 = EXECUTABLE_ORDINAL
        return None


def create_sym_hash(filename=None, data=None):
    # create the sym hash
    if filename:
        with open(filename, 'rb') as f:
            data = f.read()

    if not data:
        return

    filetype = magic.from_buffer(data[0:1024])

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

            dylib_list = []
            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_LOAD_DYLIB:
                    dylib_list.append(cmd['dylib'].decode())

            sym_list = []
            for cmd in entity.cmdlist:
                if cmd['cmd'] == MachOEntity.LC_SYMTAB:
                    for sym in cmd['symbols']:
                        if not sym['is_stab']:
                            if sym['external'] is True:
                                if sym['n_type'] == '0x00':  # 0x00 = N_UNDF
                                    library_ordinal = (sym['n_desc'] >> 8) & 0xff
                                    if library_ordinal > 0:
                                        dylib_name = get_dylib_name_by_ordinal(dylib_list, library_ordinal)
                                        if dylib_name:
                                            sym_list.append("{}.{}".format(dylib_name, sym.get('string', '').decode()))
            #                                 print("{}\t{}".format(dylib_name, sym.get('string', '').decode()))

            # print(','.join(sorted(sym_list)).encode())
            symhash = md5(','.join(sorted(sym_list)).encode()).hexdigest()
            sym_dict[entity_string] = symhash

    return sym_dict
