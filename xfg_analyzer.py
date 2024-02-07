from binaryninja import Localcall, PluginCommand, Constant, log_info, log_error
import binaryninja
import sqlite3
import sys
import os

DB_PATH = "CHANGEME/xfg/hashes.db"

def run(bv):
    conn = sqlite3.connect(DB_PATH)
    #turn all hashes into actual vars
    for f in bv.functions:
        hash_addr = f.start-8
        if bv.get_functions_at(hash_addr) == []: #address doesn't belong to another function
            if bv[hash_addr] == b'\x71': #all xfg hashes are masked with 71 AFAIK
                bv.define_data_var(f.start-8,"uint64_t", "xfg_hash")
    #annotate functions 
    hashes = set()
    types_applied = 0
    for s in bv.get_symbols_by_name("xfg_hash"):
        hash_address = s.address
        function_address = s.address+8
        func = bv.get_function_at(function_address)
        hash = bv.read_int(hash_address,8,sign=False,endian=binaryninja.enums.Endianness.BigEndian)
        #query the database
        hashes.add(hash)
        cursor = conn.execute("SELECT HASH, PROTOTYPE from HASHES where HASH=?",[hash])
        for row in cursor:
            func_proto = row[1].strip()
            func.apply_auto_discovered_type(func_proto)
            log_info("Applying function prototype: %s -> %s"%(func.name,func_proto))
            types_applied +=1 
            break
        #bv.set_comment_at(function_address,f_proto)
        #hashes.append(bv.read_int(s.address,8,sign=False))
    log_info("Total applied: %d"%types_applied)
    log_info("Total functions with XFG hash: %d"%len(list(bv.get_symbols_by_name("xfg_hash"))))
    log_info("Total unique XFG hashes: %d"%len(hashes))

if not os.path.exists(DB_PATH):
    log_error("XFG Plugin requires a database of hashes.")
    log_error("Create the database via other included scripts and adjust DB_PATH")
else:
    PluginCommand.register("XFG Analysis", "", run)