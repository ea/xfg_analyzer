import argparse
import sys
import hashlib
import sqlite3

from pycparser import parse_file,c_parser,c_generator
import pycparser
import struct

debug = False

types_table = {
"void"                   :0xe,
"char"                   :0x1,
"signed char"            :0x1,
"unsigned char"          :0x1,
"__int8"                 :0x1,
"char8_t"                :0x1,
"__int16"                :0x6,
"short int"              :0x6,
"unsigned short int"     :0x86,
"float"                  :0x11,
"int"                    :0x7,
"__int32"                :0x7,
"unsigned int"           :0x87,
"long int"               :0x10,
"unsigned long int"      :0x8a,
"double"                 :0x12,
"__int64"                :0x8,
"long  double"           :0x12,
"long long int"          :0x8,
"unsigned long long int" :0x88,
"unsigned long long" :0x88,
}



def quart_hash(d):
    return hashlib.sha256(d).digest()[0:8]

def apply_backend_masks(hash):
    hash = hash & 0xFFFDBFFF7EDFFB70
    hash = hash | 0x8000060010500070
    hash = hash | 0x1 # when hash is written before the function, this bit is set
    return hash

def get_primitive_type_hash(t):
    quals = 0x00 
    if "const" in t.quals:
        quals = quals | 0x1
    if "volatile" in t.quals:
        quals = quals | 0x2

    type_name = " ".join(t.type.names)
    type_val = 0x0
    if type_name in types_table:
        type_val = types_table[type_name]
    else:
        debug_print("WARNING: unknown primitive type: %s"%type_name)
    type_group = 0x1
    d = struct.pack("BBB",quals,type_group,type_val)
    return quart_hash(d)

def get_pointer_type_hash(t):
    #get sub type
    sub_hash = b''
    if isinstance(t.type.type,pycparser.c_ast.Struct):
        sub_hash = get_struct_type_hash(t.type)
    elif isinstance(t.type,pycparser.c_ast.TypeDecl):
        sub_hash = get_primitive_type_hash(t.type)
    elif isinstance(t.type,pycparser.c_ast.PtrDecl):
        sub_hash = get_pointer_type_hash(t.type)
    else:
        debug_print("Warning: Uknown pointer type ", type(t.type))
    quals = 0x00 
    if "const" in t.quals:
        quals = quals | 0x1
    if "volatile" in t.quals:
        quals = quals | 0x2
    type_group = 0x3
    pointer_type = 0x2 # "regular pointer" only for now, seems like function pointers and arrays are handled differently 
    d = struct.pack("BB8sB",quals,type_group, sub_hash,pointer_type)
    return quart_hash(d)

def get_struct_type_hash(t):
    struct_name = t.type.name
    quals = 0x00 
    if "const" in t.quals:
        quals = quals | 0x1
    if "volatile" in t.quals:
        quals = quals | 0x2
    type_group = 0x2
    d = struct.pack("BB%ds"%len(struct_name),quals,type_group,bytes(struct_name,'ascii'))
    return quart_hash(d)

def get_type_hash(t):
    if isinstance(t.type,pycparser.c_ast.Struct):
        return get_struct_type_hash(t)    
    elif isinstance(t,pycparser.c_ast.TypeDecl):
        return get_primitive_type_hash(t)
    elif isinstance(t,pycparser.c_ast.PtrDecl):
        return get_pointer_type_hash(t)
    else:
        debug_print("Warning: unknown hash type (not pointer nor primitive)",type(t))
        return b""

def debug_print(*args, **kwargs):
    global debug
    if debug:
        print(*args,**kwargs)


if __name__ == "__main__":

    parser = c_parser.CParser()
    generator = c_generator.CGenerator()
    conn = sqlite3.connect('hashes.db')

    ast = parse_file(sys.argv[1], use_cpp=False)
    for f_ast in ast.ext:
        data = b''
        if isinstance(f_ast,pycparser.c_ast.Decl):
            f_decl = f_ast
            f_type = f_decl.type
            f_args = f_type.args
            if f_args:
                debug_print("Function has %d parameters"%len(f_args.params))
                data += struct.pack("I",len(f_args.params))
                for param_decl in f_args.params:
                    debug_print("arg name is %s "%param_decl.name)
                    if isinstance(param_decl.type,pycparser.c_ast.PtrDecl) and isinstance(param_decl.type.type, pycparser.c_ast.IdentifierType):
                        debug_print("\t is a pointer to %s"%" ".join(param_decl.type.type.type.names))
                        if len(param_decl.type.type.quals):
                            debug_print("\t and has %s qualifiers"%param_decl.type.type.quals)
                    if isinstance(param_decl.type,pycparser.c_ast.TypeDecl) and isinstance(param_decl.type.type, pycparser.c_ast.IdentifierType):
                        #print(type(param_decl.type.type))
                        debug_print("\t is a primitive type: %s"%" ".join(param_decl.type.type.names))
                        if len(param_decl.type.quals):
                            debug_print("\t and has %s qualifiers"%param_decl.type.quals)
                    param_type_hash = get_type_hash(param_decl.type)
                    data += param_type_hash
            else:
                data += b"\x00\x00\x00\x00" # no params
            # is variadic
            data += struct.pack('<B', 0x0)
            # calling convention
            data += struct.pack('<L',0x201 & 0x0F)      

            #return type hash
            ret_type_hash = get_type_hash(f_type.type)
            data += ret_type_hash
            final_hash = apply_backend_masks(struct.unpack('<Q',quart_hash(data))[0])
            hash = struct.pack("Q",final_hash).hex()
            proto = generator.visit(f_ast)
            #print(hash,proto)            
            hash = int("0x"+hash, 16)
            conn.execute("INSERT OR IGNORE INTO HASHES (HASH, PROTOTYPE) VALUES (?,?)",(hash,proto))
    conn.commit()
    conn.close()
        