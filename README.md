# symhash #
A tool to create symbol table hashes for Mach-O executables. 

This is a python library that can either be used in your python script or used at a command line in shell scripts.

These hashes can be used to compare OSX binaries and find similar matches. The oldest and most common technique for malware detection is still an exact match of a file hash. Exact match methods have been obsolete for several years due to morphing malware and differences in embedded configurations from kits. By finding similar binaries you can detect famlilies.

# Recommended Use:

1. Create a data store for associating files and their various component hashes such as symhash
1. Generate and store symhash for as many known bad binaries from various families that you can find.
1. When you get new files to evaluate fast, if you dont find an exact match on them, compare the symhash
1. Cluster unknown files to known files using symhash
1. Cluster unknown files to each other by symhash, so that you can prioritize reversing by cluster size 

Author: Aaron Shelmire, Anomali Inc.

# Installation

```
pip install symhash
```

OR to install from source

```
# Make sure you have Python and pip installed.
git clone https://github.com/threatstream/symhash.git
cd symhash
pip install .
```

# Example Use at Command Line (using file in bin)
```
./symhash.py -f filename -v
```

# Example Use in Python Script
```python
#search through the components in the binary to find 
for cmd in entity.cmdlist:
	if cmd['cmd'] == MachOEntity.LC_SYMTAB:
		for sym in cmd['symbols']:
			if not sym['is_stab']:
				if sym['external'] is True:
					sym_list.append(sym.get('string',''))
symhash = md5(','.join(sorted(sym_list))).hexdigest()
```

# License

symhash is covered under the MIT License.  See [LICENSE](LICENSE) for more info.