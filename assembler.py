from instructions import op_table
import pandas as pd
import time
import cv2


def indexed(operand):
    operand = operand.replace(" ", '')
    if operand.__contains__(',X'):
        return True
    else:
        return False


def ranking(hexa):
    hexa = str(hexa)
    if (len(hexa) == 6):
        pass
    elif (len(hexa) == 5):
        hexa = '0' + hexa
    elif (len(hexa) == 4):
        hexa = '00' + hexa
    elif (len(hexa) == 3):
        hexa = '000' + hexa
    elif (len(hexa) == 2):
        hexa = '0000' + hexa
    elif (len(hexa) == 1):
        hexa = '00000' + hexa
    return hexa


def reading_table(url):
    df = pd.read_table(url, sep='\t', names=('Label', 'Mnemonic', 'Operand'))
    return df


def Label(lab):
    if lab != '-':
        return True
    else:
        return False


def contains(df, value):
    n = len(df)
    value = value.replace(',X', '')
    for i in range(n):
        x = str(df.iloc[i, 0])
        if value == x:
            return True
    return False


def is_string(string):
    string = str(string)
    if string.__contains__('C\''):
        return True
    else:
        return False


def remove_comments(df):
    n = len(df)
    IN = False
    for i in range(n):
        if (df.iloc[i, 0] == '.'):
            d = df.drop(i)
            IN = True
    if IN == True:
        return d
    else:
        return df


def adjust_code(label_address):
    factor = 2 ** 15
    label_address = int(label_address, 16)
    adjusted = label_address + factor
    adjusted = hex(adjusted)
    adjusted = str(adjusted)
    adjusted = adjusted.replace('0x', '')
    return adjusted


def address1(hexa):
    if (len(hexa) == 4):
        return hexa
    elif (len(hexa) == 3):
        hexa = '0' + hexa
    elif (len(hexa) == 2):
        hexa = '00' + hexa
    elif (len(hexa) == 1):
        hexa = '000' + hexa
    return hexa


def pass1(df):
    index = 0
    error_flag = False
    loc_count = 0
    df = remove_comments(df)
    l = list()
    print(df)
    Symbtab = {'Label': [], 'address': []}
    if (str(df.iloc[index, 1]).upper() == 'START'):
        loc_count = str(df.iloc[index, 2])
        Starting_address = loc_count
        Symbtab['Label'].append(df.iloc[index, 0])
        Symbtab['address'].append(address1(loc_count))
        l.append(address1(loc_count))
        l.append(address1(loc_count))
        loc_count = int(loc_count, 16)
    else:
        loc_count = '0'
    index += 1
    while (str(df.iloc[index, 1]).upper() != 'END'):
        if (df.iloc[index, 0] != '-'):
            if Symbtab['Label'].__contains__(df.iloc[index, 0]):
                error_flag = True
                raise Exception('DUPLICATE SYMBOLS!!')
            else:
                Symbtab['Label'].append(df.iloc[index, 0])
                y = hex(loc_count)
                y = str(y)
                y = y.replace('0x', '')
                Symbtab['address'].append(address1(y.upper()))
        if op_table.__contains__(df.iloc[index, 1]):
            loc_count += 3
        elif (df.iloc[index, 1] == 'WORD'):
            loc_count += 3
        elif (df.iloc[index, 1] == 'RESW'):
            loc_count += 3 * int(df.iloc[index, 2])
        elif (df.iloc[index, 1] == 'RESB'):
            loc_count += int(df.iloc[index, 2])
        elif (df.iloc[index, 1] == 'BYTE'):
            value = df.iloc[index, 2]
            value = str(value)
            if value.__contains__('C\''):
                value.replace('C\'', '')
                l.append(address1(y.upper()))
                loc_count += len(value)
            elif value.__contains__('X\''):
                value = value.replace('X\'', '')
                value = value.replace('\'', '')
                loc_count += 1
        else:
            raise Exception('INVALID OPERATION CODE!!')
        tem = hex(loc_count)
        tem = str(tem)
        tem = tem.replace('0x', '')
        l.append(address1(tem.upper()))
        index += 1
    df2 = pd.DataFrame(Symbtab)
    df2.from_dict(Symbtab, orient='index')
    df2.to_csv(r'SymbolTable.txt', header=None, index=None, sep='\t', mode='w')
    n = len(l) - 1
    l[n] = ' '
    inter_med = pd.Series(l)
    df['loc_count'] = inter_med.values
    f = open('Intermediate.txt', 'w')
    f.write('Label' + '  ' + 'Mnemonic' +' ' + 'Operand' + '\t' + 'Location')
    f.write('\n')
    for u in range(len(df)):
        if (str(df.iloc[u, 0]) == '-'):
            f.write(str(df.iloc[u, 0]).replace(' ', '') + '\t' + str(df.iloc[u, 1]).replace(' ', '') + '\t' + str(
                df.iloc[u, 2]).replace(' ', '') +
                    '\t' + str(df.iloc[u, 3]).replace(' ', ''))
        else:
            f.write(
                str(df.iloc[u, 0]).replace(' ', '') + '\t' + str(df.iloc[u, 1]).replace(' ', '') + '\t' + str(
                    df.iloc[u, 2]).replace(' ', '') +
                '\t' + str(df.iloc[u, 3]).replace(' ', ''))
        f.write('\n')
    f.close()
    return loc_count, Starting_address, df


def pass2(df, loc_index, start, length, df5):
    Symbol_table = pd.read_table('SymbolTable.txt', sep='\t', names=('Label', 'Address'))
    length = ranking(length)
    print(Symbol_table)
    block = list()
    if len(str(Symbol_table.iloc[0, 0])) > 6:
        raise Exception('NAME OF PROGRAM OUT OF BOUND')
    f = open('Objectcode.txt', 'w')
    f.write('H ' + str(Symbol_table.iloc[0, 0]) + '\t' + ranking(start) + ' ' + length + '\n')
    f.close()
    Symb = Symbol_table.to_dict('list')
    address = list(Symb['Address'])
    labels = list(Symb['Label'])
    block.append(' ')
    codes = list()
    index = 1
    lab_res = False
    Bytes_w = int(start, 16)
    W = 0
    B = 0
    while (str(df.iloc[index, 1]).upper() != 'END'):
        W = 0
        B = 0
        if (df.iloc[index, 0] != '.'):
            if (op_table.__contains__(df.iloc[index, 1])):
                op_code = op_table[df.iloc[index, 1]]
                op = str(df.iloc[index, 2])
                op = op.replace(',X', '')
                if (labels.__contains__(op)):
                    if (indexed(df.iloc[index, 2])):
                        indicator = labels.index(op)
                        label_address = address[indicator]
                        val = adjust_code(str(label_address))
                        code = op_code + val
                        codes.append(code.upper())
                        block.append(code.upper())
                    else:
                        indicator = labels.index(op)
                        label_address = address[indicator]
                        code = str(op_code) + address1(str(label_address))
                        codes.append(code.upper())
                        block.append(code.upper())
                else:
                    raise Exception('UNDEFINED SYMBOL')
            elif (df.iloc[index, 1] == 'BYTE'):
                if is_string(df.iloc[index, 2]):
                    stri = str(df.iloc[index, 2])
                    stri = stri.replace('C\'', '')
                    stri = stri.replace('\'', '')
                    s = len(stri)
                    lab_res = False
                    stri = ''.join(c.encode('hex_codec') for c in stri).upper()
                    codes.append(stri)
                    block.append(stri)
                elif str(df.iloc[index, 2]).__contains__('X\''):
                    stri = str(df.iloc[index, 2])
                    stri = stri.replace('X\'', '')
                    stri = stri.replace('\'', '')
                    s = len(stri)
                    lab_res = False
                    codes.append(stri)
                    block.append(stri)
                else:
                    lab_res = False
                    stri = df.iloc[index, 2]
                    stri = int(stri)
                    stri = str(stri)
                    if (len(stri) == 1):
                        stri = '0' + stri
                    codes.append(stri)
                    block.append(stri)
                    size = 1
            elif (df.iloc[index, 1] == 'WORD'):
                lab_res = False
                stri = df.iloc[index, 2]
                if (str(stri).__contains__('H')):
                    stri = str(stri).replace('H', '')
                    codes.append(stri)
                    block.append(stri)
                else:
                    stri = int(stri)
                    stri=hex(stri)
                    stri=str(stri)
                    stri = stri.replace('0x','')
                    stri = ranking(stri)
                    codes.append(stri.upper())
                    size = 3
                    block.append(stri)
            elif df.iloc[index, 1] == 'RESB':
                B = int(df.iloc[index, 2])
                lab_res = True
                block.append(' ')
            elif df.iloc[index, 1] == 'RESW':
                W = 3 * int(df.iloc[index, 2])
                lab_res = True
                block.append(' ')
        if ((lab_res == False and len(codes) == 10) or index == (len(df) - 2) or lab_res == True and len(codes) != 0):
            temp = list()
            t = 0
            inc = 0
            written_length_D = 30
            while (written_length_D != 0 and len(codes) != 0):
                element = codes[0]
                element = str(element)
                l = (len(element) / 2)
                t += l
                codes.remove(element)
                temp.append(element)
                written_length_D -= l
                if (written_length_D < 0):
                    break
            inc = t
            t = hex(t)
            t = str(t)
            t = t.replace('0x', '').upper()
            if (len(t) == 1):
                t = '0' + t
            offset = hex(Bytes_w)
            offset = str(offset)
            offset = offset.replace('0x', '').upper()
            f = open('Objectcode.txt', 'a')
            f.write('T ' + ranking(offset) + ' ' + t + ' ')
            m = 0
            for i in temp:
                f.write(i)
                if (m != (len(temp) - 1)):
                    f.write(' ')
            if (index != (len(df) - 2)):
                f.write('\n')
            if (lab_res == True):
                Bytes_w += B
                Bytes_w += W
                Bytes_w += inc
            else:
                Bytes_w += inc
            lab_res = False
        elif len(codes) == 0 and lab_res == True:
            Bytes_w += W
        index += 1
    block.append(' ')
    list_file = pd.Series(block)
    f.write('\n')
    f.write('E ' + ranking(start))
    f.close()
    df5['object_code'] = list_file.values
    f = open('list_file.txt', 'w')
    for u in range(len(df5)):
        if (str(df.iloc[u, 0]) == '-'):
            f.write(str(df.iloc[u, 0]).replace(' ', '') + '\t' + str(df.iloc[u, 1]).replace(' ', '') + '\t' + str(
                df.iloc[u, 2]).replace(' ', '') +
                    '\t' + str(df.iloc[u, 3]).replace(' ', '') + '\t' + str(df.iloc[u, 4]).replace(' ', ''))
        else:
            f.write(
                str(df.iloc[u, 0]).replace(' ', '') + '\t' + str(df.iloc[u, 1]).replace(' ', '') + '\t' + str(
                    df.iloc[u, 2]).replace(' ', '') +
                '\t' + str(df.iloc[u, 3]).replace(' ', '') + '\t' + str(df.iloc[u, 4]).replace(' ', ''))
        f.write('\n')
    f.close()


start_time = time.time()
df = reading_table('program.txt')
df.fillna('-', inplace=True)
loc_count, starting, dfx = pass1(df)
st = int(starting, 16)
length = loc_count - st
length = hex(length)
length = str(length)
length = length.replace('0x', '')
pass2(df, loc_count, starting, length, dfx)
end_time = time.time()
print("--- %s seconds ---" % (end_time - start_time))
