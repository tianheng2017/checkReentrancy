from __future__ import print_function
import sys
import re
from execute_instruction import *
from values import seen_configuration
from values import MyGlobals
from misc import *

# 模拟和分析以太坊智能合约的执行
# 本函数接收一系列的参数，包括操作码（ops）、当前执行位置（pos）、堆栈（stack）、存储（storage）、存储位置的布尔值（is_storage）、内存（mmemory）、数据（data）、配置（configurations）、搜索操作（search_op）、搜索函数（search_function）、跳转深度（jumpdepth）、调用深度（calldepth）、调试标志（debug）、从区块链读取数据的标志（read_from_blockchain）、源代码映射（sourceMap）和源代码路径（SourcePath）
# 函数首先检查是否已经标记了合约为易受攻击的，如果是，则停止执行
# 然后，它记录访问过的节点数量，并检查是否超过了预设的最大访问节点数
# 函数进入一个循环，不断执行操作码，直到程序计数器没有移动或者满足停止条件
# 在循环中，函数会检查当前操作码是否需要改变跳转深度或调用深度，并在达到预设的最大跳转深度或调用深度时停止搜索
# 如果当前操作码是搜索操作之一，函数会保存路径条件，并使用相应的搜索函数来判断是否存在安全漏洞
# 函数还处理了几种特殊情况，包括CALLDATALOAD和CALLDATASIZE操作码，并为这些情况创建新的执行分支
def execute_one_block( ops , stack , pos , trace, storage , is_storage , mmemory, data, configurations, search_op, search_function, jumpdepth, calldepth, debug, read_from_blockchain, sourceMap, SourcePath):
    global s, stop_search, search_condition_found, visited_nodes

    if MyGlobals.stop_search : return 

    MyGlobals.visited_nodes += 1
    if MyGlobals.visited_nodes > MyGlobals.MAX_VISITED_NODES: return
    
    first = True
    newpos = pos
    while (first or newpos != pos) and not MyGlobals.stop_search:
        first = False
        pos = newpos    

        if pos >= len(ops) or pos < 0:
            if debug: print('\033[94m[+] Reached bad/end of execution\033[0m')
            return False
        
        if debug: 
            if len(sourceMap) > 0 and pos < len(sourceMap):
                print('[ %3d %3d %5d] : %4x : %12s : %s  [ %s %s ]' % (calldepth, jumpdepth, MyGlobals.visited_nodes, ops[pos]['id'], ops[pos]['o'], ops[pos]['input'],sourceMap[pos]['s'],sourceMap[pos]['l']) )
            else:
                print('[ %3d %3d %5d] : %4x : %12s : %s  ' % (calldepth, jumpdepth, MyGlobals.visited_nodes, ops[pos]['id'], ops[pos]['o'], ops[pos]['input']) )

        if pos == 0: 
            calldepth += 1
            jumpdepth = 0
        if ops[pos]['o'] == 'JUMPDEST': jumpdepth += 1
        if( jumpdepth > MyGlobals.MAX_JUMP_DEPTH): 
            if debug:print ('\033[95m[-] Reach MAX_JUMP_DEPTH\033[0m' )
            return
        if( calldepth > MyGlobals.MAX_CALL_DEPTH): 
            if debug:print ('\033[95m[-] Reach MAX_CALL_DEPTH\033[0m' )
            return

        if pos == 0 or ops[pos]['o'] == 'JUMPDEST' or (pos > 0 and ops[pos-1]['o'] == 'JUMPI'):
            if seen_configuration( configurations, ops, pos, stack, mmemory, storage): 
                if debug:print ('\033[95m[-] Seen configuration\033[0m' )
                return

        if ops[pos]['o'] in search_op:

            if debug:
                print('\033[96m[+] Reached %s at %x \033[0m'  % (ops[pos]['o'], ops[pos]['id'] ) )
                print_stack(stack)
 
            trace = MyGlobals.s.assertions()

            new_search_condition_found, stop_expanding_the_search_tree =  search_function(ops,pos,stack,storage, is_storage ,trace,debug,sourceMap,SourcePath)
            MyGlobals.search_condition_found = MyGlobals.search_condition_found or new_search_condition_found

            if MyGlobals.stop_search or stop_expanding_the_search_tree:  return

        newpos, halt = execute( ops, stack, pos, storage, is_storage ,mmemory, data, trace, calldepth, debug, read_from_blockchain  )

        if halt:
            if debug: 
                print('\033[94m[+] Halted on %s on line %x \033[0m' % (ops[pos]['o'],ops[pos]['id']))

            if ops[pos]['o'] in ['STOP','RETURN','SUICIDE']:
                if not MyGlobals.search_condition_found:
                    stack   = []
                    mmemory = {}
                    newpos = 0

                    if not debug:
                        print('%d' % calldepth,end='')
                        if MyGlobals.exec_as_script:
                            sys.stdout.flush()
                    continue
                else:
                    MyGlobals.stop_search = True
                    return
            else:
                return 
            
        if pos == newpos:
            si = ops[pos]
            if si['o'] == 'JUMPI':
                if len(stack) < 2:
                    if debug: print('\033[95m[-] In JUMPI (line %x) the stack is too small to execute JUMPI\033[0m' % pos )
                    return False
        
                addr = stack.pop()
                des = stack.pop()

                if is_undefined(des):
                    if debug: print('\033[95m[-] In JUMPI the expression cannot be evaluated (is undefined)\033[0m'   )
                    return False
                sole = '  * sole * '
                if is_good_jump( ops, pos+1, debug ): 
                    MyGlobals.s.push()
                    MyGlobals.s.add( des['z3'] == 0)
                    try:
                        if MyGlobals.s.check() == sat:
                            storage2 = copy.deepcopy(storage)
                            stack2 = copy.deepcopy(stack)
                            trace2 = copy.deepcopy(trace)
                            mmemory2 = copy.deepcopy(mmemory)
                            data2 = copy.deepcopy(data)
                            is_storage2 = copy.deepcopy(is_storage)
                            if debug: print('\t'*8+'-'*20+'JUMPI branch 1 (go through)')
                            sole = ''
                            execute_one_block(ops,stack2, pos + 1,trace2, storage2, is_storage2 , mmemory2, data2, configurations,    search_op, search_function, jumpdepth+1, calldepth, debug, read_from_blockchain ,sourceMap, SourcePath)


                    except Exception as e:
                        print ("Exception: "+str(e))

                    MyGlobals.s.pop()
                if MyGlobals.stop_search: 
                    return
                if not is_fixed(addr):
                    if debug: print('\033[95m[-] In JUMPI the jump address cannot be determined \033[0m'  % jump_dest )
                    return False
    
                jump_dest = get_value( addr )
                if( jump_dest <= 0):
                    if debug: print('\033[95m[-] The jump destination is not a valid address : %x\033[0m'  % jump_dest )
                    return False

                new_position= find_pos(ops, jump_dest )
                if( new_position < 0):
                    if debug: print('\033[95m[-] The code has no such jump destination: %s at line %x\033[0m' % (hex(jump_dest), si['id']) )
                    return False
                if is_good_jump( ops, new_position, debug ): 
                    MyGlobals.s.push()
                    MyGlobals.s.add( des['z3'] != 0)
                    try:
                        if MyGlobals.s.check() == sat:

                            if debug:
                                if ops[pos]['id'] -  MyGlobals.last_eq_step < 5:
                                    print('\t'*8+'-'*18+'\033[96m %2d Executing function %x \033[0m' % (calldepth, MyGlobals.last_eq_func) )
                            storage2 = copy.deepcopy(storage)
                            stack2 = copy.deepcopy(stack)
                            trace2 = copy.deepcopy(trace)
                            mmemory2 = copy.deepcopy(mmemory)
                            data2 = copy.deepcopy(data)
                            is_storage2 = copy.deepcopy(is_storage)
                            if debug: print( ('\t'*8+'-'*20+'JUMPI branch 2 (jump) on step %x' + sole ) % ops[pos]['id'] )
                            execute_one_block(ops,stack2,   new_position,   trace2, storage2,  is_storage2,  mmemory2, data2, configurations,    search_op, search_function,  jumpdepth, calldepth, debug, read_from_blockchain ,sourceMap,SourcePath)
                    except Exception as e:
                        print ("Exception: "+str(e))
                    MyGlobals.s.pop()
                return 
            elif si['o'] == 'CALLDATALOAD':
                addr = stack.pop()
                text = str(addr['z3'])
                regex = re.compile('input[0-9]*\[[0-9 ]*\]')
                match = re.search( regex, text)
                if match:
                    sm = text[match.start():match.end()]
                    random_address = get_hash(sm) >> 64
                    
                    r2 = re.compile('\[[0-9 ]*\]')
                    indmat = re.search( r2, sm )
                    index = -2
                    if indmat:
                        index = int( sm[indmat.start()+1:indmat.end()-1] )

                    total_added_to_solver = 0
                    if index>= 0 and ('data-'+str(calldepth)+'-'+str(index)) in data:
                        data[('data-'+str(calldepth)+'-'+str(index))] = BitVec(sm+'d',256)
                        MyGlobals.s.push()
                        MyGlobals.s.add( data[('data-'+str(calldepth)+'-'+str(index))] == random_address  )
                        total_added_to_solver = 1
                    for st in stack:
                        if 'z3' in st:
                            st['z3'] = simplify(substitute( st['z3'], (BitVec(sm,256),BitVecVal(random_address, 256))))
                    for st in mmemory:
                        if 'z3' in mmemory[st]:
                            mmemory[st]['z3'] = simplify(substitute( mmemory[st]['z3'], (BitVec(sm,256),BitVecVal(random_address, 256))))
                    addr = simplify(substitute(addr['z3'], (BitVec(sm,256),BitVecVal(random_address, 256)) ) )
                    branch_array_size = [0,1,2]
                    for one_branch_size in branch_array_size:
                        storage2 = copy.deepcopy(storage)
                        stack2 = copy.deepcopy(stack)
                        trace2 = copy.deepcopy(trace)
                        mmemory2 = copy.deepcopy(mmemory)
                        data2 = copy.deepcopy(data)
                        is_storage2 = copy.deepcopy(is_storage)

                        data2['data-'+str(calldepth)+'-' + str(addr)] = BitVecVal(one_branch_size,256)
                        for i in range(one_branch_size):
                            data2['data-'+str(calldepth)+'-'+ str(addr.as_long()+32+32*i)] = BitVec('input'+str(calldepth)+'['+('%s'%(addr.as_long()+32+32*i))+']',256)

                        stack2.append( {'type':'constant','step':ops[pos]['id'], 'z3':BitVecVal( one_branch_size, 256)})

                        MyGlobals.s.push()
                        MyGlobals.s.add( BitVec('input'+str(calldepth)+('[%x'%addr.as_long())+']',256) == one_branch_size)

                        execute_one_block(ops,stack2,   pos+1,  trace2, storage2, is_storage2 ,  mmemory2, data2, configurations,    search_op, search_function,  jumpdepth, calldepth, debug, read_from_blockchain, sourceMap ,SourcePath)

                        MyGlobals.s.pop()


                    for ta in range(total_added_to_solver):
                        MyGlobals.s.pop()
                else:
                    if debug: 
                        print('\033[95m[-] In CALLDATALOAD the address does not contain symbolic variable input[*]\033[0m' )
                        print( addr )
                    return 

                return

            elif si['o'] == 'CALLDATASIZE':
                    storage2 = copy.deepcopy(storage)
                    stack2 = copy.deepcopy(stack)
                    trace2 = copy.deepcopy(trace)
                    mmemory2 = copy.deepcopy(mmemory)
                    data2 = copy.deepcopy(data)
                    is_storage2 = copy.deepcopy(is_storage)

                    if -1 not in data2:
                        data2['inputlength-'+str(calldepth)] = BitVec('inputlength-'+str(calldepth), 256)
                    stack2.append( {'type':'constant','step':ops[pos]['id'], 'z3': data2['inputlength-'+str(calldepth)]} )
                    execute_one_block(ops,stack2,   pos+1,  trace2, storage2,  is_storage2 , mmemory2, data2, configurations,    search_op, search_function,  jumpdepth, calldepth, debug, read_from_blockchain, sourceMap ,SourcePath)
                    branch_array_size = [0,8,8+1*32,8+2*32]
                    for one_branch_size in branch_array_size:
                        storage2 = copy.deepcopy(storage)
                        stack2 = copy.deepcopy(stack)
                        trace2 = copy.deepcopy(trace)
                        mmemory2 = copy.deepcopy(mmemory)
                        data2 = copy.deepcopy(data)
                        is_storage2 = copy.deepcopy(is_storage)

                        stack2.append( {'type':'constant','step':ops[pos]['id'], 'z3': BitVecVal(one_branch_size,256)} )

                        execute_one_block(ops,stack2,   pos+1,  trace2, storage2, is_storage2 ,  mmemory2, data2, configurations,    search_op, search_function,  jumpdepth, calldepth, debug, read_from_blockchain, sourceMap ,SourcePath)
                    return
            else:
                print('\033[95m[-] Unknown %s on line %x \033[0m' % (si['o'],ops[pos]['id']) )
                return 