from __future__ import print_function
from parse_code import *
from values import get_params, initialize_params, MyGlobals, clear_globals
from execute_block import *  
from z3.z3util import get_vars

# 此函数使用Z3定理证明器来检查合约是否容易受到重入攻击
# 它接收操作码（ops）、当前位置（pos）、堆栈（stack）、存储（storage）、存储位置的布尔值（is_storage）、追踪信息（trace）、调试标志（debug）、源代码映射（sourceMap）和源代码路径（SourcePath）作为输入
# 函数首先检查追踪中的每个表达式，找出所有可能更新存储的变量
# 然后检查调用的交易金额是否大于存储中的某个值，这可能是一个潜在的重入条件
# 接着设置了一个阈值（2300 gas），这是发送者和转账提供的gas。如果gas大于这个阈值，合约可能容易受到重入攻击
# 最后函数返回一个布尔值，表示是否发现了重入条件
def ether_reentrancy( ops, pos, stack, storage, is_storage,trace, debug = False, sourceMap = [] , SourcePath = ''):
    global stop_search
    solver = Solver()
    solver.add(trace)
    for i in trace:
        if is_expr(i):
            list_vars = get_vars(i)
            for var in list_vars:
                # 检查是否在更新了状态的情况下，调用可以再次执行
                if var in is_storage:
                    pos = is_storage[var]
                    if pos in storage:
                        solver.add(var == storage[pos][0]['z3'])

    trans_mount = stack[-3]['z3']
    if trans_mount in is_storage:
        pos = is_storage[trans_mount]
        if pos in storage:
            solver.add(storage[pos][0]['z3'] != 0)

    # 设置阈值为2300，这是发送者和转账提供的gas
    # 如果gas大于这个阈值，标记该合约容易受到重入攻击的影响
    solver.add(stack[-1]['z3'] > BitVecVal(2300,256))
    solver.add(stack[-3]['z3'] > BitVecVal(int(get_params('contract_balance',''), 10), 256))
    ret_val = not (solver.check() == unsat)
    MyGlobals.stop_search = ret_val
    if MyGlobals.stop_search:
        MyGlobals.pos = pos

    return ret_val, ret_val

# 此函数用于执行一个特定深度的搜索来检查是否存在重入漏洞
# 它初始化一些全局变量，执行一个区块，并调用ether_reentrancy函数来检查重入条件
# 如果在任何深度发现了重入条件，搜索将停止，并且函数返回相应的结果
def run_one_check( max_call_depth, ops, SourcePath, debug, read_from_blockchain,sourceMap):
    print('[ ]\033[1m 搜索深度: %d   : \033[0m' % (max_call_depth) , end = '')

    initialize_params(read_from_blockchain)
    clear_globals()

    global MAX_CALL_DEPTH
    MyGlobals.MAX_CALL_DEPTH    = max_call_depth

    storage = {}    
    stack   = []
    mmemory = {}
    data = {}
    trace   = []
    configurations = {}
    is_storage = {}

    # 一旦CALL执行，判断合约是否易受攻击
    execute_one_block(ops,stack,0, trace, storage, is_storage , mmemory, data, configurations, ['CALL'], ether_reentrancy, 0, 0, debug, read_from_blockchain,  sourceMap, SourcePath )

# 本函数用于检查合约是否容易受到重入攻击
# 先解析合约的字节码，并检查是否存在CALL操作码，因为CALL是可能导致重入的指令
# 如果没有发现CALL指令，函数将输出一条消息并返回False，表示没有发现重入漏洞
# 如果存在CALL指令，它将继续执行深度搜索，并在发现重入条件时输出警告信息
# 函数返回布尔值，表示是否发现了重入漏洞
def check(contract_bytecode, SourcePath, debug = False, read_from_blockchain = False, sourceMap=[] ):

    print('\033[94m[ ] 检查合约是否可重入攻击\033[0m\n')
    print('[ ] 合约bytecode  : %s...' % contract_bytecode[:50])
    print('[ ] Bytecode长度  : %d' % len(contract_bytecode) )
    print('[ ] 调试模式      : %s' % debug)

    ops = parse_code( contract_bytecode, debug )

    # 合约中不包含CALL操作码，因此不可能存在相关的漏洞
    if not code_has_instruction( ops, ['CALL']) :
        print('\n\033[92m[-] 代码中不包含CALL操作码，因此它不会受到漏洞的影响\033[0m')
        return False
    
    if debug: print_code( contract_bytecode, ops )

    global symbolic_vars

    # 符号化变量
    MyGlobals.symbolic_vars = ['CALLVALUE','CALLER','NUMBER','TIMESTAMP','BLOCKHASH','BALANCE','ADDRESS','ORIGIN','EXTCODESIZE']
    MyGlobals.symbolic_sha = True
    
    # 允许在SLOAD和SSTORE指令中使用符号地址
    MyGlobals.symbolic_load= True

    for i in range( 1 , MyGlobals.max_calldepth_in_normal_search + 1 ):
        run_one_check( i, ops, SourcePath, debug, read_from_blockchain,sourceMap)

        if MyGlobals.stop_search: 
            break

    if MyGlobals.stop_search:
        print('\n\n\033[91m[-]  发现重入攻击漏洞! \033[0m\n')
        print_SourceCode(MyGlobals.pos, sourceMap, SourcePath)
        return True
    
    print('\n\033[92m[-] 未发现重入攻击漏洞 \033[0m')

    return False