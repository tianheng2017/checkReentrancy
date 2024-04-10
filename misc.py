from __future__ import print_function
from values import MyGlobals
from hashlib import *
from z3 import *


def print_stack(stack):
    print('\033[90m------------------------------------- STACK -------------------------------------')
    for s in stack[::-1]:
        if 'z3' in s:
            if is_bv_value( simplify(s['z3'])): print('%10s : %4x  : %x' % (s['type'],s['step'],simplify(s['z3']).as_long() ) )
            else: print('%10s : %4x  : %s' % (s['type'],s['step'], simplify(s['z3']) ) )
        else:
            print('%10s : %4x  ' % (s['type'],s['step']) )
    print('\033[0m')

def print_storage(storage):
    print('************************************ STORAGE ************************************')
    for fl in storage:
        for s in storage[fl]:
            print('\033[91m[ %64x ] \033[0m : ' % (fl), end='' )        
            if is_bv_value( simplify(s['z3'])): print('%x' % (simplify(s['z3']).as_long() ) )
            else: print('%s' % (simplify(s['z3']) ) )

def print_memory(mmemory):
    print('************************************ MEMORY ************************************')
    for m in mmemory:
        fl = mmemory[m]
        print('\033[91m[ %64x ] \033[0m : ' % (m), end='' )        
        if fl['type'] == 'undefined' : print('undefined' )
        elif is_bv_value( simplify(fl['z3'])): print('%x' % (simplify(fl['z3']).as_long() ) )
        else: print('%s' % (simplify(fl['z3']) ) )            
        

def print_trace(trace):
    print('++++++++++++++++++++++++++++ Trace ++++++++++++++++++++++++++++')
    for o in trace:
        print('%6x  : %2s : %12s : %s' % (o['id'],o['op'],o['o'] , o['input']) )


def print_SourceCode(pos, sourceMap, SourcePath):
    if MyGlobals.stop_search == True and pos < len(sourceMap) and SourcePath != '':
        with open(SourcePath,'r') as file:
            code = file.readlines()
        line = getLineFromPos(SourcePath, int(sourceMap[pos]['s'])) 
        print("The vulnerability may occur near line : %d \n" % line)

        if line-3 >= 0 :
            print("%d : %s" % (line-2, code[line-3]),end='')
        if line-2 >= 0 :
            print("%d : %s" % (line-1, code[line-2]),end='')
        
        print("%d : %s" % (line, code[line-1]),end='')

        if line <= len(code) :
            print("%d : %s" % (line+1, code[line]),end='')
        if line+1 <= len(code) :
            print("%d : %s" % (line+2, code[line+1]),end='')
        print("\n")

def getLineFromPos(File, pos):
    with open(File, 'r') as myfile:
        code=myfile.readlines()

    if pos == 0:
        return 1

    lines = 0
    count = 0
    while count < pos :
        if lines < len(code):
            count += len(code[lines])
            lines += 1
        else:
            print("Cannot find the corresponding row!\n")
            break

    return lines

def get_hash(txt):
    k = md5()
    k.update(txt.encode('utf-8'))
    return int(k.hexdigest(),16)
