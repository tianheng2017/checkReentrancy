from __future__ import print_function
import copy
from math import *
from instruction_list import *
from parse_code import *
from values import get_params
from values import MyGlobals
from hashlib import *
from _pysha3 import keccak_256
from z3 import *
from misc import *

def is_fixed(s): return s['type'] == 'constant' and is_bv_value(simplify(s['z3']))
def is_undefined(s): return s['type'] == 'undefined'
def get_value(s): return  simplify(s['z3']).as_long()

def power(y, x, n):
    if x == 0: 
        return 1
    elif (x%2==0):  
        return power((y*y)%n,x//2,n)%n
    else: 
        return (y*power((y*y)%n,x//2,n))%n
def store_in_memory( mmemory, addr, value ):
    for i in range(addr+1, addr+32):
        if i in mmemory:

            if not is_undefined(mmemory[i]):

                if is_undefined( value ): 
                    mmemory[i]['type'] = 'undefined'
                    continue

                obytes = (i - addr);
                old_value = mmemory[i]['z3']
                new_value = ( old_value & (2**(8*obytes) - 1) ) ^ (value['z3'] << (8*obytes) )
                
                if new_value == 0: del mmemory[i]
                else: mmemory[i]['z3'] = new_value


    for i in range(addr-31,addr):
        if i in mmemory:

            if not is_undefined(mmemory[i]):

                if is_undefined( value ): 
                    mmemory[i]['type'] = 'undefined'
                    continue

                obytes = addr - i;
                old_value = mmemory[i]['z3']
                new_value = ( old_value & ( (2**(8*obytes)-1) << (8*(32-obytes) ) ) )   ^ ( value ['z3'] >> (8*obytes ) )

                if new_value == 0: del mmemory[i]
                else: mmemory[i]['z3'] = new_value
    mmemory[addr] = value;

def unary( o1, step, op='NONE' ):
    if is_undefined(o1): return {'type':'undefined','step':step}
    z1 = simplify(o1['z3'])
    if      op == 'NOT': z3 = ~z1
    elif    op == 'ISZERO': z3 = If(z1 == 0, BitVecVal(1, 256), BitVecVal(0, 256))
    else:
        print('did not process unary operation %s ' % op )
        print(o1)
        return {'type':'undefined','step':step} 
    return {'type':'constant','step':step, 'z3': z3} 

def binary( o1, o2 , step, op='NONE'):
    if is_fixed(o1):
        val = simplify(o1['z3']).as_long()
        if op in ['MUL','AND','DIV','SDIV'] and 0 == val: return {'type':'constant','step':step, 'z3':BitVecVal(0,256) }
        if op in ['XOR','ADD'] and 0 == val: return o2
        
    if is_fixed(o2):
        val = simplify(o2['z3']).as_long()
        if op in ['MUL','AND','DIV','SDIV'] and 0 == val: return {'type':'constant','step':step, 'z3':BitVecVal(0,256) }
        if op in ['XOR','ADD'] and 0 == val: return o1

    if is_undefined(o1) or is_undefined(o2): return {'type':'undefined','step':step}

    z1 = simplify(o1['z3'])
    z2 = simplify(o2['z3'])

    if   op =='AND' : z3 = z1 & z2
    elif op =='OR'  : z3 = z1 | z2
    elif op =='XOR' : z3 = z1 ^ z2
    
    elif op =='ADD' : z3 = z1 + z2
    elif op =='SUB' : z3 = z1 - z2 
 
    elif op =='EXP' : 
        if is_bv_value(z1) and is_bv_value(z2):
            z3 = BitVecVal( power (z1.as_long(), z2.as_long(), 2**256), 256 )
        else: 
            return {'type':'undefined','step':step}

    elif op =='DIV' : z3 = UDiv(z1,z2) 

    elif op =='SDIV': z3 = z1/z2 

    elif op =='MOD' : z3 = URem(z1,z2)
    
    elif op =='SMOD' : z3 = z1 % z2 

    elif op =='MUL' : z3 = z1 * z2 

    elif op =='GT'  : z3 = If(UGT(z1, z2), BitVecVal(1, 256), BitVecVal(0, 256))
    
    elif op =='SGT' : z3 = If(z1 > z2, BitVecVal(1, 256), BitVecVal(0, 256))

    elif op =='LT'  : z3 = If(ULT(z1, z2), BitVecVal(1, 256), BitVecVal(0, 256))

    elif op =='SLT' : z3 = If(z1 < z2, BitVecVal(1, 256), BitVecVal(0, 256))

    elif op =='EQ'  : 
        global last_eq_step, last_eq_func

        if is_bv_value(z1) and z1.as_long() < 2**32 and z1.as_long() > 2**28: 
            MyGlobals.last_eq_step = step
            MyGlobals.last_eq_func = z1.as_long()
        if is_bv_value(z2) and z2.as_long() < 2**32 and z2.as_long() > 2**28: 
            MyGlobals.last_eq_step = step
            MyGlobals.last_eq_func = z2.as_long()
        z3 = If(z1 == z2, BitVecVal(1, 256), BitVecVal(0, 256))
    else:
        print('did not process binary operation %s  ' % op)
        print(o1)
        print(o2)
        return {'type':'undefined','step':step} 

    return {'type':'constant','step':step, 'z3': z3} 

def ternary( o1, o2 , o3, step, op='NONE'):

    if o3['type'] == 'constant' and is_bv_value(simplify(o3['z3'])) and 0 == simplify(o3['z3']).as_long(): return {'type':'constant','step':step, 'z3':BitVecVal(0,256) }

    z1 = simplify(o1['z3'])
    z2 = simplify(o2['z3'])
    z3 = simplify(o3['z3'])

    if   op == 'ADDMOD': return {'type':'constant', 'step':step, 'z3': (z1+z2) % z3 }

    elif op == 'MULMOD': return {'type':'constant', 'step':step, 'z3': (z1*z2) % z3 }

    else:
        print('did not process ternary operation %s  ' % op)
        print(o1)
        print(o2)
        print(o3)
        return {'type':'undefined','step':step} 

def is_good_jump(ops,pos, debug):
    return True

def execute( code, stack, pos, storage, is_storage ,mmemory, data, trace, calldepth, debug, read_from_blockchain  ):
    op = code[pos]['o']
    halt = False
    executed = True
    step = code[pos]['id']

    if op not in allops:
        print('Unknown operation %s at pos %x' % (op,pos) )
        return pos,True

    if allops[op][1] > len(stack): 
        if debug: print('Not enough entries in the stack to execute the operation %8s  at step %x: required %d, provided %d' % (op,code[pos]['id'], allops[op][1], len(stack)) )
        return pos, True
    start_stack_size = len(stack)
    final_stack_size = len(stack) - allops[op][1] + allops[op][2]

    args = []
    if op.find('SWAP') < 0 and op.find('DUP') < 0 and op not in ['JUMPI']:
        for i in range( allops[op][1] ): args.append( stack.pop() )
    

    if op in ['ISZERO','NOT']: 
        stack.append( unary ( args[0] ,step, op ) )
        
    elif op in ['ADD','MUL','SUB','DIV','SDIV','MOD','SMOD','EXP','AND','OR','XOR', 'LT','GT','SLT','SGT','EQ']:
        stack.append( binary (  args[0] , args[1] , step , op ) )

    elif op in ['ADDMOD','MULMOD']:
        stack.append( ternary( args[0], args[1], args[2], step, op ) )

    elif op == 'SIGNEXTEND':
        if not is_fixed(args[0]) or not is_fixed(args[1]): 
            stack.append( {'type':'undefined','step':step} )

        else:  

            o = get_value(args[1])
            t = 256 - 8*( get_value(args[0]) + 1 )
            tbit = (o >> t ) & 1
            n = 0
            for i in range(256): 
                n ^= (tbit if i<= t else ((o>>i)&1)) << i
            stack.append( {'type':'undefined','step':step, 'z3':BitVecVal( n, 256 ) } )
    elif op == 'SHA3':
        addr  = simplify(args[0]['z3'])
        offset= simplify(args[1]['z3'])
        exact_address = addr.as_long() if is_bv_value(addr) else -1
        exact_offset  = offset.as_long() if is_bv_value(offset) else -1
        res = {'type':'undefined','step':step}
        if exact_address >= 0 and exact_offset >= 0:
            if (exact_offset % 32) == 0 :
                val = ''
                all_good = True
                for i in range(int(exact_offset/32)):
                    if (exact_address + i*32) not in mmemory or not is_fixed(mmemory[exact_address+i*32]): 
                        all_good = False
                        break
                    val += '%064x' % get_value(mmemory[exact_address + i*32])

                if all_good:

                    k = keccak_256()
                    k.update(val.encode('utf-8'))
                    digest = k.hexdigest() 
                    res = {'type':'constant','step':step, 'z3':BitVecVal(int(digest,16), 256) }

        if MyGlobals.symbolic_sha and is_undefined(res):
            res = {'type':'constant','step':step, 'z3': BitVec('sha-'+str(step)+'-'+str(calldepth),256) }

        stack.append( res )

    elif op.find('PUSH') >= 0: stack.append( {'type':'constant','step':step, 'z3':BitVecVal(int(code[pos]['input'],16), 256)} )
    elif op.find('DUP' ) >= 0: stack.append( copy.deepcopy( stack[-int(op[3:]) ] ) )
    elif op.find('SWAP') >= 0:
        tmp1 = stack[-1]
        tmp2 = stack[-int(op[4:])-1 ]
        stack[-1] = tmp2
        stack[-int(op[4:]) -1] = tmp1
    elif op in MyGlobals.symbolic_vars:
        stack.append( {'type':'constant','step':step, 'z3': BitVec(op+'-'+str(calldepth),256) } ) 

    elif op in MyGlobals.findpos_vars:
        stack.append( {'type':'constant','step':step, 'z3': BitVec(op+'-'+str(calldepth)+'-'+str(pos),256) } ) 

    elif op == 'NUMBER':        stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('block_number',''),16), 256)} )
    elif op == 'GASLIMIT':      stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('gas_limit',''),16), 256)} )
    elif op == 'TIMESTAMP':     stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('time_stamp','')), 256)} )
    elif op == 'CALLVALUE':     stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('call_value',''),16), 256)} )
    elif op == 'ADDRESS':       stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('contract_address',''), 16), 256)} )
    elif op == 'ORIGIN':        stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('contract_address',''), 16), 256)} )
    elif op == 'GASPRICE':      stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('gas_price',''), 16), 256) } )
    elif op == 'COINBASE':      stack.append( {'type':'constant','step':step, 'z3': BitVecVal(0,256)} )
    elif op == 'DIFFICULTY':    stack.append( {'type':'constant','step':step, 'z3': BitVecVal(0,256)} )
    elif op == 'CALLER':        stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('my_address',''), 16), 256) } )
    elif op == 'GAS':           stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('gas',''),16), 256) } )
    elif op == 'MSIZE':         stack.append( {'type':'constant','step':step, 'z3': BitVecVal(len(mmemory), 256) } )
    elif op == 'BLOCKHASH':     stack.append( {'type':'constant','step':step, 'z3': BitVecVal(0x123,256)} )
    elif op == 'BALANCE':       stack.append( {'type':'constant','step':step, 'z3': BitVecVal(int(get_params('contract_balance',''), 10), 256)} )
    elif op == 'POP':           pass
    elif op.find('LOG') >= 0:   pass
    elif op == 'CODECOPY':      pass
    elif op == 'JUMPDEST':      
        if not is_good_jump(code, pos, debug): 
            return pos, True
    elif op in ['STOP','RETURN','REVERT', 'INVALID', 'SUICIDE']:    halt = True
    elif op in ['CALLDATALOAD']:
        addr = args[0]
        if is_fixed( addr ):
            addr = get_value(addr)
            if ('data-'+str(calldepth)+'-' + str(addr)) not in data:
                data['data-'+str(calldepth)+'-' + str(addr)] = BitVec('input'+str(calldepth)+'['+str(addr)+']', 256)
            stack.append( {'type':'constant','step':step, 'z3':data['data-'+str(calldepth)+'-' + str(addr)] } )
        elif is_undefined(addr):
            if debug:
                print ('\033[95m[-] In CALLDATALOAD the input address cannot be determined at step %x: \033[0m' % code[pos]['id'] )
                print( addr )
            return pos, True
        else:
            stack.append( args[0] )
            return pos, False
    elif op in ['CALLDATASIZE']:
        return pos, False
    elif op == 'CALL':
        if is_fixed(args[5]) and is_fixed(args[6]):
            addr  = get_value( args[5] )
            value = get_value( args[6] )
            if value < 10000:
                for i in range(int(value/32)):
                    mmemory[addr + 32 * i] = { 'type':'undefined','step':step }
        stack.append( {'type':'constant','step':step, 'z3':BitVec('call_at_step_'+str(step), 256) & 0x1} )     
    elif op == 'CALLDATACOPY': 
        memaddr = args[0]  
        datapos = args[1]
        length  = args[2]
        if not is_fixed(memaddr) or not is_fixed( datapos ) or not is_fixed( length ):
            if debug: 
                print('\033[95m[-] In CALLDATACOPY the memory address or datapos or length cannot be determined \033[0m' )
                print(memaddr)
                print(datapos)
                print(length)
            return pos, True
        memaddr = get_value ( memaddr )
        datapos = get_value ( datapos )
        length  = get_value ( length  )
        if length % 32 != 0:
            if debug:
                print('\033[95m[-] In CALLDATACOPY the length of array (%d) is not multiple of 32 \033[0m' % length )
            return pos, True
        for i in range( int( length / 32 )):
            data[ datapos + 32 * i ] = BitVec('input'+str(calldepth)+'['+str(datapos + 32 * i )+']',256)
            store_in_memory( mmemory, memaddr + 32 * i , {'type':'constant','step':step,'z3':data[ datapos + 32 * i ]} )
    elif op == 'CALLCODE':          stack.append( {'type':'constant','step':step, 'z3':BitVecVal(0,256)} )
    elif op == 'DELEGATECALL':      stack.append( {'type':'constant','step':step, 'z3':BitVecVal(0,256)} )
    elif op == 'EXTCODESIZE':       stack.append( {'type':'constant','step':step, 'z3':BitVecVal(0,256)} )
    elif op == 'CREATE': stack.append( {'type':'constant','step':step, 'z3':BitVecVal(0,256)} )
    elif op == 'MLOAD':
        addr = args[0]
        if is_undefined(addr):
            if debug:print('\033[95m[-] The MLOAD address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True

        addr = simplify(addr['z3'])

        if is_bv_value(addr):

            exact_address = addr.as_long()
            if exact_address in mmemory: res = copy.deepcopy(mmemory[exact_address])
            else: 
                res = {'type':'constant','step':step, 'z3': BitVecVal(0, 256) }
            stack.append( res )

        else:
            if debug:print('\033[95m[-] The MLOAD address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True

    elif op == 'MSTORE':


        addr = args[0]
        if is_undefined(addr) or not is_bv_value( simplify(addr['z3']) ) :
            if debug:print('\033[95m[-] The MSTORE the write address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True

        t = copy.deepcopy( args[1] )
        addr = get_value(addr)

        store_in_memory( mmemory, addr, t )

    elif op in ['MSTORE8']:
        addr = args[0]
        value= args[1]

        if not is_fixed(addr) :
            if debug:print('\033[95m[-] The MSTORE8 the write address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True
        if not is_fixed(value) :
            if debug:print('\033[95m[-] The MSTORE8 value is undefined \033[0m' % code[pos]['id'] )
            return pos, True

        ea = get_value(addr)
        ev = get_value(value) % 256

        if int(ea/32)*32 not in mmemory: 
            mmemory[int(ea/32)*32] = {'type':'constant','step':step, 'z3':BitVecVal(ev << (31- (ea%32)), 256) }
        elif is_fixed( mmemory[int(ea/32)*32]['z3'] ):
            v = get_value( mmemory[int(ea/32)*32]['z3'] )
            v = (v & (~BitVecVal(0xff,256) << (31- (ea%32)))) ^ (ev << (31- (ea%32)))
            mmemory[int(ea/32)*32]['z3'] = v

    elif op == 'SLOAD':

        addr = args[0]

        if is_undefined(addr):
            if debug:print('\033[95m[-] The SLOAD address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True

        addr = simplify(addr['z3'])
        if is_bv_value(addr):

            exact_address = addr.as_long()

            if exact_address in storage:
                total_values = len(storage[exact_address])
                if total_values == 0:
                    print('In SLOAD the list at address %x has no elements ' % exact_address)
                    exit(0)
                    return pos, True
                else : 
                    res = copy.deepcopy(storage[exact_address][0])

                    
            else:
                if MyGlobals.web3 is not None and read_from_blockchain:
                    value = MyGlobals.web3.eth.getStorageAt( get_params('contract_address',''), exact_address )
                else:
                    value = 'sload-'+str(step)+'-'+str(calldepth)
                t = {'type':'constant','step':step, 'z3': BitVec(value, 256) }

                storage[exact_address] = [ t ]
                res = copy.deepcopy(t)

                is_storage[ res['z3'] ] = exact_address 

            stack.append( res )
        else:
            if MyGlobals.symbolic_load:
                exact_address = str(addr)
                if exact_address in storage:
                    total_values = len(storage[exact_address])
                    if total_values == 0:
                        print('In SLOAD the list at address %x has no elements ' % exact_address)
                        exit(0)
                        return pos, True
                    else :  
                        res = copy.deepcopy(storage[exact_address][0])
                else:
                    value = 'sload-'+str(step)+'-'+str(calldepth)
                    t = {'type':'constant','step':step, 'z3': BitVec(value, 256) }
                    storage[exact_address] = [ t ]
                    res = copy.deepcopy(t)

                    is_storage[ res['z3'] ] = exact_address 
                stack.append( res )

            else:
                if debug:print('\033[95m[-] The SLOAD address on %x  cannot be determined\033[0m' % code[pos]['id'] )
                return pos, True



    elif op == 'SSTORE':


        addr = args[0]
        if is_undefined(addr):
            if debug:print('\033[95m[-] The SSTORE address on %x  cannot be determined\033[0m' % code[pos]['id'] )
            return pos, True

        t = copy.deepcopy( args[1] )

        if is_bv_value( simplify(addr['z3']) ):
            va = get_value( addr )
            storage[va] = [ t ]

            if t['type'] == 'constant': is_storage[ t['z3'] ] = va

        else:
            if MyGlobals.symbolic_load:
                storage[str(simplify(addr['z3']))] = [ t ]
                if t['type'] == 'constant': is_storage[ t['z3'] ] = str(simplify(addr['z3']))
            else:
                if debug:
                    print ('\033[95m[-] In SSTORE the write address cannot be determined at step %x: \033[0m' % code[pos]['id'] )
                    print( addr )
                return pos, True
            
    elif op == 'JUMP':

        addr = args[0]

        if not is_fixed( addr ):
            if debug: print('\033[95m[-] In JUMP the address cannot be determined \033[0m'  )
            return pos, True
        
        jump_dest = get_value( addr )
        if( jump_dest <= 0):
            if debug: print('\033[95m[-] The JUMP destination is not a valid address : %x\033[0m'  % jump_dest )
            return pos, True
        
        new_position= find_pos(code, jump_dest )

        if( new_position < 0):
            if debug: print('\033[95m[-] The code has no such JUMP destination: %s at line %x\033[0m' % (hex(jump_dest), code[pos]['id']) )
            return pos, True

        if not is_good_jump(code, new_position, debug): 
            return pos, True
        return new_position, False
    elif op == 'JUMPI': return pos , False

    elif op == 'BYTE':
        byte_no = args[0]
        word    = args[1]
        if is_undefined(word) or is_undefined(byte_no): 
            res = {'type':'undefined','step':step}
        else:                                           
            res = {'type':'constant','step':step, 'z3': (word['z3'] >> (8*(31-byte_no['z3'])) ) & 0xff }

        stack.append( res )
    else:
        executed = False

    if executed and final_stack_size != len(stack):
        print('Incorrect final stack size after executing %s at step %x' % (op,step))
        print(len(stack))
        print(final_stack_size)
        exit(2)

    return pos + 1, halt



