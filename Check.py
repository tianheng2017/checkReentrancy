import argparse,subprocess,sys
import shutil
import json

# 依赖检查
found_depend = False
try:
    import z3
except:
    print("\033[91m[-] python z3模块未安装")
    found_depend = True
if not (subprocess.call("solc --version", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0):
    print("\033[91m[-] python solc模块未安装")
    found_depend = True
if found_depend:
    sys.exit(1)

import reentrancy
from values import MyGlobals
from contracts import *

global debug, read_from_blockchain
def main(args):
    # 命令行参数解析
    parser = argparse.ArgumentParser()
    parser.add_argument("-s","--soliditycode", type=str,   help="第一个参数合约路径，第二个参数合约溟城", action='store', nargs=2)
    parser.add_argument("--debug",        help="打印扩展调试信息 ", action='store_true')
    args = parser.parse_args( args )

    # 是否开启debug
    if args.debug: MyGlobals.debug = True

    # 打印一些分隔符
    print('\n'+'=' * 100)

    # sol源码路径
    SourcePath = args.soliditycode[0]

    # 构造编译后的路径
    FilePath = args.soliditycode[0].replace('/','_').replace('.','_')

    # 编译合约
    compile_contract(args.soliditycode[0], FilePath)
    
    # 得到合约bytecode
    contract_code_path = FilePath+'/' + args.soliditycode[1] + '.bin-runtime'
    
    # 如果编译后没有得到相关bytecode，说明合约不存在
    if not os.path.isfile( contract_code_path ):  
        print('\033[91m[-] 合约 %s 不存在\033[0m' % args.soliditycode[1] )
        return

    # 得到合约sourcemap
    sourcemap_path = FilePath + '/' + "combined.json"

    # 如果sourcemap不存在
    if not os.path.isfile( sourcemap_path ):  
        print('\033[91m[-] SourceMap 不存在\033[0m' )
        return
    
    with open(sourcemap_path, 'r') as fw:
        # 加载json
        injson = json.load(fw)

        # 拿到与本次检测有关的部分
        sourceMapJson = injson['contracts'][args.soliditycode[0]+':'+args.soliditycode[1]]['srcmap-runtime']

        # 得到源代码中字节码的映射关系
        sourceMap = sourcemap_corresponding(sourceMapJson)

    # 读取合约源代码
    with open(contract_code_path,'r') as f: code = f.read(); f.close()

    # 处理源代码中的\n、\r、空格
    code = code.replace('\n','').replace('\r','').replace(' ','')

    # 开始检测
    reentrancy.check(code, SourcePath, MyGlobals.debug, MyGlobals.read_from_blockchain, sourceMap)

    # 删除编译后的文件夹
    shutil.rmtree(FilePath)

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])