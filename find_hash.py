import sqlite3
import sys
conn = sqlite3.connect('hashes.db')
f = open(sys.argv[1],"r")
for l in f:        
    if len(l.strip()) == 0:
        continue 
    hash = int("0x"+l.strip(), 16)
    cursor = conn.execute("SELECT HASH, PROTOTYPE from HASHES where HASH=?",[hash])
    for row in cursor:
        print("%x %s"%(row[0],row[1].strip()))
        break