# gather all data from malware/benign opcode basic blocks

import os

benignDir = 'benign/'
malwareDir = 'malware/'
resultFile = 'statistics.csv'
total = {}
opcodeThreshold = 0.1
totalFileCount = 0

def extraction(path):
    fileCount = 0
    result = {}
    for name in os.listdir(path):
        target = path + name
        print(target)

        ext = os.path.splitext(target)[1]
        if ext != '.txt':
            print('\t[ERROR] Wrong extension')
            print()
            continue
        
        fileCount += 1
        with open(target, 'r') as r:
            oneBlock = 'a'

            while oneBlock != '':
                oneBlock = r.readline()
                oneBlock = oneBlock.strip()

                if oneBlock == '':
                    continue
                
                if oneBlock not in total.keys():
                    total[oneBlock] = 1
                else:
                    total[oneBlock] += 1

                if oneBlock not in result.keys():
                    result[oneBlock] = 1
                else:
                    result[oneBlock] += 1
    
    for k in result.keys():
        result[k] = round(result[k] / fileCount, 4)
    global totalFileCount
    totalFileCount += fileCount

    return result

print('benign opcode')
print()
benign = extraction(benignDir)
print()
print('malware opcode')
print()
malware = extraction(malwareDir)

count = 0
for v in total.values():
    count += v
print(count)
print(count / totalFileCount)

print()
print('removing insignificant blocks...')
count = 0
deleter = [k for k, v in total.items() if v / totalFileCount < opcodeThreshold]

for d in deleter:
    count += 1
    del total[d]
print('complete')
print(count)
print()

with open(resultFile, 'w') as w:
    allOpcode = total.keys()
    
    w.write(',total,benign,malware,b-m\n')

    for opcode in allOpcode:
        if total[opcode] == 1:
            continue
        
        if len(opcode) > 30:
            cutopcode = opcode[:30] + '...'
            w.write(str(cutopcode) + ',')
        else:
            w.write(str(opcode) + ',')

        w.write(str(total[opcode]) + ',')
        
        bvalue = 0
        mvalue = 0

        if opcode in benign.keys():
            bvalue = benign[opcode]
            w.write(str(bvalue) + ',')
        else:
            w.write('0,')

        if opcode in malware.keys():
            mvalue = malware[opcode]
            w.write(str(mvalue) + ',')
        else:
            w.write('0,')

        w.write(str(bvalue - mvalue))
        
        w.write('\n')

print()
print('DONE!')