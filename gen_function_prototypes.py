import itertools
from jinja2 import Template
import sys
# ones that are commented out are aliases
types = ["void",
        "char",
        #"signed char","unsigned char",
        #"__int8",
        #"char8_t",
        #"__int16",
        "short int",
        "unsigned short int",
        "float",
        "int",
        #"__int32",
        "unsigned int",
        "long int",
        "unsigned long int",
        "double",
        #"__int64",
        #"long double",
        "long long int",
        #"unsigned long long int",
        "unsigned long long"
        #,"struct in_addr" # we don't actually need to define a struct, we can just use it as a type 
        # if you want enums or unions , same thing , just use struct keyword instead of enum/union  
        ]
types += [x + " *" for x in types] #add all types as pointers
types += ["const " + x  for x in types] # add all types as consts and pointers
#types += ["volatile " + x  for x in types] # add all types as volatile and consts and pointers 

template = """
{{ret_type}} fname( {%- for param_type in param_types -%} {{param_type}} arg{{loop.index}}{{ "," if not loop.last }} {%- endfor -%});
"""
j2_template = Template(template)

print(len(types))
max_func_params = 3
f = open(sys.argv[1],"w")
i = 0
for ret_type in types:
    for pn in range(0,max_func_params+1):
        for c in itertools.product(types,repeat=pn):
            #print(ret_type,c)
            f.write(j2_template.render({"ret_type":ret_type,"param_types":c}))
    i+=1
f.close()

