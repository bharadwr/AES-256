#!/usr/bin/env python3
# Homework Number: 4
# Name: Rtvik Sriram Bharadwaj
# ECN Login: bharadwr
# Due Date: 12/2/2019

from BitVector import *
import sys
from os import rename, remove, path
import operator

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []


def shiftRows(temp_shift, statearray, op):
    for i in range(1, 4):
        for j in range(0, 4):
            temp_shift[(op(j, i)) % 4] = statearray[j][i]
        for j in range(0, 4):
            statearray[j][i] = temp_shift[j]


def subBytes(statearray, bytesTable):
    for i in range(4):
        for j in range(4):
            statearray[i][j] = BitVector(intVal=bytesTable[int(statearray[i][j])])


def mixColumns(statearray, round_num):
    two_times = BitVector(bitstring='00000010')
    three_times = BitVector(bitstring='00000011')
    for i in range(4):
        temp0 = (two_times.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
               (three_times.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
               statearray[i][2] ^ \
               statearray[i][3]

        temp1 = (two_times.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                (three_times.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                statearray[i][3] ^ \
                statearray[i][0]

        temp2 = (two_times.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                (three_times.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                statearray[i][0] ^ \
                statearray[i][1]

        temp3 = (two_times.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                (three_times.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                statearray[i][1] ^ \
                statearray[i][2]

        statearray[i][0], statearray[i][1], statearray[i][2], statearray[i][3] = temp0, temp1, temp2, temp3


def invMixColumns(statearray):
    zeroE, zeroB, zeroD, zero9 = BitVector(bitstring='00001110'), BitVector(bitstring='00001011'), BitVector(bitstring='00001101'), BitVector(bitstring='00001001')

    for i in range(4):
        temp0 = (zeroE.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                (zeroB.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                (zeroD.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                (zero9.gf_multiply_modular(statearray[i][3], AES_modulus, 8))

        temp1 = (zeroE.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                (zeroB.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                (zeroD.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                (zero9.gf_multiply_modular(statearray[i][0], AES_modulus, 8))

        temp2 = (zeroE.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                (zeroB.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                (zeroD.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                (zero9.gf_multiply_modular(statearray[i][1], AES_modulus, 8))

        temp3 = (zeroE.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                (zeroB.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                (zeroD.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                (zero9.gf_multiply_modular(statearray[i][2], AES_modulus, 8))

        statearray[i][0], statearray[i][1], statearray[i][2], statearray[i][3] = temp0, temp1, temp2, temp3


def addRoundKey(statearray, key_words, round_num, op):
    for i in range(4):
        for j in range(4):
            statearray[i][j] ^= key_words[(4 * op(round_num, 1)) + i][8 * j:8 + (8 * j)]


def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal =
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words


def gee(keyword, round_num_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_num_constant
    round_num_constant = round_num_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_num_constant


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def encrypt(inputfile, outputfile, key):
    with open(outputfile, 'wb') as FILEOUT:
        f = open('encrypted_hex.txt', 'w')
        key_words = gen_key_schedule_256(key)
        bv = BitVector(filename=inputfile)
        statearray = [[0 for x in range(4)] for x in range(4)]
        temp_shift = [0] * 4
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) != 128:
                    bitvec.pad_from_right(128 - len(bitvec))

                # Filling in statearray and XORing
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)] ^ key_words[i][8 * j:8 + (8 * j)]

                for round_num in range(14):
                    # SubBytes
                    subBytes(statearray, subBytesTable)
                    # ShiftRows
                    shiftRows(temp_shift, statearray, operator.sub)
                    # ColumnMixing
                    if round_num is not 13:
                        mixColumns(statearray, round_num)
                    # Add round_num Key
                    addRoundKey(statearray, key_words, round_num, operator.add)

                for i in range(4):
                    for j in range(4):
                        statearray[i][j].write_to_file(FILEOUT)
                        f.write(statearray[i][j].get_bitvector_in_hex())
        f.close()


def decrypt(inputfile, outputfile, key):
    temp_shift = [0] * 4
    key_words = gen_key_schedule_256(key)
    bv = BitVector(filename=inputfile)
    statearray = [[0 for x in range(4)] for x in range(4)]
    with open(outputfile, 'wb') as FILEOUT:
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) != 128:
                    bitvec.pad_from_right(128 - len(bitvec))

                # Filling in statearray and XORing
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)] ^ key_words[-(4 - i)][8 * j:8 + (8 * j)]

                for round_num in range(14, 0, -1):
                    # Inverse shift rows
                    shiftRows(temp_shift, statearray, operator.add)
                    # Inverse SubBytes
                    subBytes(statearray, invSubBytesTable)
                    # Add round_num Key
                    addRoundKey(statearray, key_words, round_num, operator.sub)
                    # Inverse ColumnMixing
                    if round_num is not 1:
                        invMixColumns(statearray)

                for i in range(4):
                    for j in range(4):
                        statearray[i][j].write_to_file(FILEOUT)


if __name__ == '__main__':
    if path.isfile("key.txt") is False or path.isfile("message.txt") is False:
        exit(1)
    subBytesTable, invSubBytesTable = genTables()
    with open("key.txt", 'r') as KEY:
        key = BitVector(textstring=KEY.readline().strip())
        encrypt('message.txt', 'encrypted.txt', key)
        decrypt('encrypted.txt', 'decrypted.txt', key)
    remove("encrypted.txt")
    rename("encrypted_hex.txt", "encrypted.txt")
    exit(0)
