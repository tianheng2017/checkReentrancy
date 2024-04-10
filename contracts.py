from __future__ import print_function
import os.path
from subprocess import Popen, PIPE, STDOUT
import subprocess
import os

def compile_contract(filename, to_addr):
    print('\033[1m[ ] 编译合约 %s ... \033[0m' % filename, end='')
    source_file = filename
    if (not os.path.isfile(source_file) ):
        print('\033[91m[-] 合约文件 %s 不存在\033[0m' % source_file )
        return

    p = Popen(['solc','--bin-runtime',source_file,'-o',  to_addr ,'--overwrite'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    p.wait()

    subprocess.run('solc --combined-json srcmap-runtime '+source_file + ' > ' + to_addr + '/combined.json',shell=True,stdout=PIPE, stdin=PIPE, stderr=STDOUT)

    solo = ''
    while p.poll() is None:
        l = p.stdout.readline()
        solo += bytes.decode(l)      
    if 'Error' in solo:
        print(solo)
        print('\033[91m[-] 编译合约失败 \033[0m')
        exit()

    p.stdout.close()
    p.stdin.close()

    print('\033[92m 编译完成 \033[0m')

def sourcemap_corresponding(sourceMapJson):
    sourceMap = list()
    parsed1 = sourceMapJson.split(';')

    for i in parsed1:
        tmp = i.split(':')
        while len(tmp) < 3:
            tmp.append('')
        t = {'s':tmp[0],'l':tmp[1],'f':tmp[2]}
        sourceMap.append(t)
    
    for i in range(len(sourceMap)):
        if sourceMap[i]['f'] == '':
                sourceMap[i]['f'] = sourceMap[i-1]['f']


    for i in range(len(sourceMap)):
        if sourceMap[i]['f'] == '-1':
            sourceMap[i] = sourceMap[i-1]
        
        else:
            if sourceMap[i]['s'] == '':
                sourceMap[i]['s'] = sourceMap[i-1]['s']
            if sourceMap[i]['l'] == '':
                sourceMap[i]['l'] = sourceMap[i-1]['l']

    return sourceMap