# Recovering function prototypes by bruteforcing XFG Hashes

This repository contains scripts for generating and looking up eXtended Flow Guard hashes. 

An extended writeup of how this works is available in issue 22 of International Jouranl Of Proof Of Concept || GTFO.

My work on this PoC was greatly simplified by folks at Quarkslab who have performed extensive reverse engineering of relevant parts of MS' compiler. Their in-depth writeup on how XFG hashes are being calculated can be read here: https://blog.quarkslab.com/how-the-msvc-compiler-generates-xfg-function-prototype-hashes.html


Note: this in no way "breaks" the XFG as exploit mitigation, it simply abuses its side effects to illuminate functions with no symbols. 

In short, XFG as implemented on Windows extends, and makes more strict, Control Flow Guard exploitation mitigation by limiting possible targets of indirect function calls to not only valid function entry points, but to functions with matching signature. 
To do so, an XFG hash is computed for each function and a check against it is performed during runtime. Hashes are based on just the function prototype (meaning, calling convention, arguments and their types). As such, we can precompute them for known types and later look them up for functions in unknown binaries. 

If the lookup is successful, we can be 100% certain of the exact number and types of all the arguments as well as the function's return value. This can be immenseley useful for binaries and functions with no public symbols. 

I ivnite you to read the complete article in PoC||GTFO, served from a nearby mirror. 

The scripts are:
 - gen_function_prototypes.py - simply outputs a file containing all possible prototypes with given types
 - gen_hash_from_ast.py - reads a .c file, parses it and calculates the hash and saves it in a database (meant to be used on files generated by gen_function_prototypes.py)
 - xfg_analyzer.py - Binary Ninja plugin that searches the binary for XFG hashes, looks them up in the database 
 - find_hash.py - simple shortcut to look up given hashes in the database

To use these scripts, you would first modify `gen_function_prototypes.py` to add "primitive types", structs or enums that are specific for the target you are looking at. Also, you'll want to choose up to how many arguments you want to brute force. Up to 3 takes a minute, up to 4 a day... 

After function prototypes of all combinations are generated, you'll want to run `gen_hash_from_ast.py` which will parse the previously generated file line by line and generate the corresponding XFG hash. 
When that has completed, you will have an SQLite database of function prototypes with their matching XFG hashes. A very simple Binary Ninja plugin is included in `xfg_analyzer.py`. When run against an XFG protected binary, it will find all XFG hashes, look them up in the database and, if a match is found, apply the new function prototype to the defined function.

Know that this is only a PoC. To be really useful, a giant database of hashes (possibly seeded with all struct/enum names from Windows' header files) should be generated and made available for online lookups. Additionally, expanding this idea to C++ XFG hashes would be a very fun project. 

Feel free to use the code in this repository in any way. If you do find it useful, I'd like to hear from you. 
 
- ea

