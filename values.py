import copy
from z3 import *

def get_params(param, input):

    if (param+str(input)) in MyGlobals.st:
        return MyGlobals.st[param+str(input)]
    else:
        print('need to set the parameters: %s ' % (param+str(input) ) )
        exit(4)

def is_params(param,input):
    return (param+str(input)) in MyGlobals.st 

def set_params(param, input, value):
    global st
    MyGlobals.st[param+str(input)] = value      

def initialize_params(read_from_blockchain, c_address = ''):
    global st
    MyGlobals.st = {}
    MyGlobals.st['my_address'] = MyGlobals.adversary_account
    MyGlobals.st['contract_address'] = c_address
    if read_from_blockchain:
        MyGlobals.st['contract_balance'] = str(MyGlobals.web3.eth.getBalance(c_address)+1).zfill(64)
    else:
        MyGlobals.st['contract_balance'] = '7' * 64
    MyGlobals.st['gas'] = ('765432').zfill(64)
    MyGlobals.st['gas_limit'] = ('%x' % 5000000).zfill(64)
    MyGlobals.st['gas_price'] = ('123').zfill(64)
    MyGlobals.st['time_stamp'] = ('%x' % 0x7687878).zfill(64)
    MyGlobals.st['block_number'] = ('545454').zfill(64)
def print_params():
    for s in MyGlobals.st:
        print('%20s : %s' % (s, str(MyGlobals.st[s])))
def create_configuration( stack, mmemory, storage):
    nc = {}
    nc['stack']   = copy.deepcopy(stack)
    nc['mmemory'] = copy.deepcopy(mmemory)
    nc['storage'] = copy.deepcopy(storage)
    return nc
def add_configuration( step, configurations, nc):
    if step in configurations: configurations[step].append( nc )
    else:configurations[step] = [nc]
def configuration_exist(step, configurations, nc):
    if step not in configurations:
        return False
    found = False
    for os in configurations[step]:
        if os['stack'] != nc['stack'] : continue
        if os['mmemory'] != nc['mmemory']: continue
        if( os['storage'] != nc['storage'] ):continue
        found = True
        break
    return found 
def seen_configuration( configurations, ops, position, stack, mmemory, storage):
        op = ops[position]['o']
        step = ops[position]['id']
        nc = create_configuration( stack, mmemory, storage)
        if configuration_exist(step, configurations, nc): 
            return True
        else:
            add_configuration( step, configurations, nc)
                
        return False
        

class MyGlobals(object):
    MAX_JUMP_DEPTH          = 60
    MAX_CALL_DEPTH          = 0
    MAX_VISITED_NODES       = 2000
    max_calldepth_in_normal_search = 1
    ETHER_LOCK_GOOD_IF_CAN_CALL = True
    st = {}
    s = None
    SOLVER_TIMEOUT = 10000

    search_condition_found = False
    stop_search = False
    pos = -1
    visited_nodes = 0

    last_eq_step = -1
    last_eq_func = -1

    symbolic_vars = []
    findpos_vars = []
    no_function_calls = 0
    function_calls = {}
    symbolic_sha = False
    symbolic_load = False
    symbolic_sload = False

    port_number = '8545'
    confirming_transaction ='0x3094c123bd9ffc3f41dddefd3ea88e4296e45015b62e892f8bdf9d1b645ef2d2'
    etherbase_account = '0x69190bde29255c02363477462f17e816a9533d3a'
    adversary_account = '5a1cd1d07d9f59898c434ffc90a74ecd937feb12'
    sendingether_account = '564625b3ae8d0602a8fc0fe22c884b091098417f'
    send_initial_wei = 44
    web3 = None

    debug = False
    read_from_blockchain = False
    checktype = 0
    exec_as_script = False

def clear_globals():
    MyGlobals.s = Solver()
    MyGlobals.s.set("timeout", MyGlobals.SOLVER_TIMEOUT)
    MyGlobals.search_condition_found = False
    MyGlobals.stop_search = False
    MyGlobals.pos = -1
    MyGlobals.visited_nodes = 0
    MyGlobals.no_function_calls = 0
    MyGlobals.function_calls = {}