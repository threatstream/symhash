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

try:
    from symhash.machoinfo import MachOEntity, MachOParser, MachOParserError
except:
    log.error("machoinfo is required - if installation did not work, retreive"
              "machoinfo.py from https://raw.githubusercontent.com/crits/crits_services/master/machoinfo_service/machoinfo.py")
    exit(-1)


def create_sym_hash(filename):
    # create the sym hash
    with open(filename, 'rb') as f:
        filedata = f.read()

    with magic.Magic() as m:
        filetype = m.id_filename(filename)

    if 'Mach-O' not in filetype:
        log.error("symhash only operates on Mach-O Executable files")

    macho_parser = MachOParser(filedata)

    try:
        macho_parser.parse()
    except MachOParserError as e:
        log.error("Error %s", e)
        return None

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
