# gather all data from malware/benign opcode basic blocks

import os
import numpy

benignDir = 'benign/'
malwareDir = 'malware/'
resultFile = 'opcode.csv'
opcodeThreshold = 0.05
totalFileCount = 0
total = {}

excepts1 = '''
movjmp jmp leajmp cmpb__ ldrcmpb__ movcmpjnz bl_ b__ movbl_ movb__ 
ldrcbz tesjz_ subjmp cbz movtesjz_ ldrb__ movcmpb__ ret addbl_ ldrldrcmpb__
cbn movaddjmp movret movmovbl_ addb__ ldrtstb__ ldrcbn ldaldfret movtesjnz movmovtesjz_
movcmpjz_ movmovcaljmp movmovcmpjz_ ldrbl_ movcbz ldrmovbl_ ldaldastfret movaddbl_ movleamovxorcalmovjmp movmovcaltesjz_
ldpret movmovret subb__ movmovmovcaljmp ldrmovmovbl_ subldrbx_ ldacalret puspusmovpusmovpuscalmovjmp ldraddbl_ addjmp
'''
excepts1 = excepts1.split()

excepts0 = '''
decjz_ movmovsubjz_ cmpjle cmpjz_ or_jmp xortessetleatesjnz pusjmp tesjnz decjnz cmpjbe 
cmpjg_ puscaladdmovtesjz_ cmpja_ movshlandor_tesjnz ldcbr. lealeacaltesjz_ xortessetleajmp andmovmovshlor_addjmp movpopret movaddsubaddcmpja_
puscalpopmovcmpjz_ or_tesjz_ jnz cmpjnz incjmp jb_ puspusjmp tesjge or_movjmp puspopjmp
puspuscalpuscalmovret leacmpja_ puscalpopret calret puscaljmp cmpjmp calmovcalmovjmp jg_ movincmovcmpjb_ andmovmovshljmp
calmovcalor_jmp stlbr. puspuspuscaladdtesjnz movmovcalmovcmpjbe decdecjz_ movandjmp puscalpopcmpjz_ puscaladdmovpusmovtesjz_ puspopcmpjz_ xortesjnz
'''
excepts0 = excepts0.split()

def summarizeOpcodeFromDir(path):
    allResults = []
    for name in os.listdir(path):
        target = path + name
        print(target)

        ext = os.path.splitext(target)[1]
        if ext != '.txt':
            print('\t[ERROR] Wrong extension')
            print()
            continue
        
        result = {}
        with open(target, 'r') as r:
            global totalFileCount
            totalFileCount += 1
            oneBlock = 'a'

            while oneBlock != '':
                oneBlock = r.readline()
                oneBlock = oneBlock.strip()

                if oneBlock == '':
                    continue

                if oneBlock not in result.keys():
                    result[oneBlock] = 1
                else:
                    result[oneBlock] += 1
        
        global total
        for r in result.keys():
            if r in total.keys():
                total[r] += 1
            else:
                total[r] = 1

        allResults.append(result)
    print()
    return allResults

print('benign opcode')
print()
benign = summarizeOpcodeFromDir(benignDir)
print('malware opcode')
print()
malware = summarizeOpcodeFromDir(malwareDir)
print(len(total))



for e1 in excepts1:
    print('b-m malware')
    target = []
    for m in malware:
        if e1 in m.keys():
            target.append(m[e1])
        else:
            target.append(0)
    print(e1, numpy.std(target))

    print('b-m benign')
    target = []
    for b in benign:
        if e1 in b.keys():
            target.append(b[e1])
        else:
            target.append(0)
    print(e1, numpy.std(target))

for e0 in excepts0:
    print('m-b malware')
    target = []
    for m in malware:
        if e0 in m.keys():
            target.append(m[e0])
        else:
            target.append(0)
    print(e0, numpy.std(target))

    print('m-b benign')
    target = []
    for b in benign:
        if e0 in b.keys():
            target.append(b[e0])
        else:
            target.append(0)
    print(e0, numpy.std(target))

with open(resultFile, 'w') as w:
    print()
    print('removing insignificant blocks...')
    deleter = [k for k, v in total.items() if v / totalFileCount < opcodeThreshold]
    
    for d in deleter:
        if d in excepts0 or d in excepts1:
            deleter.remove(d)

    for d in deleter:
        del total[d]
    print('complete')
    print()

    print(len(total))
    print()

    w.write('m(1)/b(0)')

    for opcode in total.keys():
        w.write(',' + str(opcode))
    w.write('\n')

    print('malware opcode recording...')
    for m in malware:
        w.write('1')
        for opcode in total.keys():
            if opcode in m.keys():
                w.write(',' + str(m[opcode]))
            else:
                w.write(',0')
        w.write('\n')
    print('complete')
    print()

    print('benign opcode recording...')
    for b in benign:
        w.write('0')
        for opcode in total.keys():
            if opcode in b.keys():
                w.write(',' + str(b[opcode]))
            else:
                w.write(',0')
        w.write('\n')
    print('complete')
    print()

print('DONE!')