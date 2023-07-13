from idautils import *
from idc import *
from idaapi import *

class dictionary(dict):
    def __init__(self):
        self = dict()

    def add(self, key, value):
        self[key] = value

xref_dict = dictionary()

for segea in Segments():
    
    if (idc.get_segm_name(segea) == ".text"): #check if in .text segment
       for funcea in Functions(segea, get_segm_end(segea)):
            count = 0
            for xrefs in XrefsTo(funcea, flags=0):
                if (str(XrefTypeName(xrefs.type)) in "Code_Near_Call" ):
                    count+=1
            if count != 0: # don't list functions without referation
                xref_dict.add(hex(funcea), count)            

print(sorted(xref_dict.items(), key=lambda x:x[1]))
