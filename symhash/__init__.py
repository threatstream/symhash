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
import sys
from hashlib import md5

import magic
import ssdeep

from symhash.machoinfo import MachOEntity, MachOParser, MachOParserError


def parse_macho(filename=None, data=None):
    if filename:
        if os.path.isfile(filename):
            with open(filename, 'rb') as f:
                data = f.read()
        else:
            sys.exit("Error: {} is not a file.".format(filename))

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

    return macho_parser


def get_dylib_name_by_ordinal(dylib_list, library_ordinal, basename_only = False):
    if library_ordinal > 0 and library_ordinal <= 253:
        if basename_only:
            return os.path.basename(dylib_list[library_ordinal - 1])
        else:
            return dylib_list[library_ordinal - 1]
    elif library_ordinal in (0, 254, 255):  # 0 = invalid, 254 = DYNAMIC_LOOKUP_ORDINAL, 255 = EXECUTABLE_ORDINAL
        return None


def get_dylib_list(entity):
    dylib_list = []
    for cmd in entity.cmdlist:
        if cmd['cmd'] == MachOEntity.LC_LOAD_DYLIB:
            dylib_list.append(cmd['dylib'].decode())

    return dylib_list


def get_import_symbol_list(entity, dylib_list):
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
                                    # print("{}\t{}".format(dylib_name, sym.get('string', '').decode()))

    return sym_list


def create_sym_hash(filename=None, data=None):
    macho_parser = parse_macho(filename, data)
    sym_dict = {}

    for entity in macho_parser.entities:
        if entity.magic_str != 'Universal':
            dylib_list = get_dylib_list(entity)
            sym_list = get_import_symbol_list(entity, dylib_list)
            # print(','.join(sorted(sym_list)).encode())
            # print("Number of symbols: {}".format(len(sym_list)))
            symhash = md5(','.join(sorted(sym_list)).encode()).hexdigest()
            entity_string = "{} {} {}".format(entity.cpu_type_str, entity.filetype_str, entity.magic_str)
            sym_dict[entity_string] = symhash

    return sym_dict


def create_sym_fuzzyhash(filename=None, data=None):
    macho_parser = parse_macho(filename, data)
    sym_fuzzy_dict = {}

    for entity in macho_parser.entities:
        if entity.magic_str != 'Universal':
            dylib_list = get_dylib_list(entity)
            sym_list = get_import_symbol_list(entity, dylib_list)
            # print(','.join(sorted(sym_list)).encode())
            # print("Number of symbols: {}".format(len(sym_list)))
            symfuzzyhash = ssdeep.hash(','.join(sorted(sym_list)).encode())
            entity_string = "{} {} {}".format(entity.cpu_type_str, entity.filetype_str, entity.magic_str)
            sym_fuzzy_dict[entity_string] = symfuzzyhash

    return sym_fuzzy_dict
