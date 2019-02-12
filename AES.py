#!/usr/bin/env python3
# Homework Number: 4
# Name: Rtvik Sriram Bharadwaj
# ECN Login: bharadwr
# Due Date: 12/2/2019

from BitVector import *
import sys
from os import rename, remove, path
import operator

AESMOD = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []


def shiftRows(tShift, initializationVector, op):
    for outer_loop in range(1, 4):
        for inner_loop in range(0, 4):
            tShift[(op(inner_loop, outer_loop)) % 4] = initializationVector[inner_loop][outer_loop]
        for inner_loop in range(0, 4):
            initializationVector[inner_loop][outer_loop] = tShift[inner_loop]


def subBytes(initializationVector, bytesTable):
    for outer_loop in range(0, 4, 1):
        for inner_loop in range(0, 4, 1):
            initializationVector[outer_loop][inner_loop] = BitVector(intVal=bytesTable[int(initializationVector[outer_loop][inner_loop])])


def mixColumns(initializationVector, two, three):
    for outer_loop in range(0, 4, 1):
        temp0, temp1, temp2, temp3 = (two.gf_multiply_modular(initializationVector[outer_loop][0], AESMOD, 8)) ^ (three.gf_multiply_modular(initializationVector[outer_loop][1], AESMOD, 8)) ^ initializationVector[outer_loop][2] ^ initializationVector[outer_loop][3], (two.gf_multiply_modular(initializationVector[outer_loop][1], AESMOD, 8)) ^ (three.gf_multiply_modular(initializationVector[outer_loop][2], AESMOD, 8)) ^ initializationVector[outer_loop][3] ^ initializationVector[outer_loop][0], (two.gf_multiply_modular(initializationVector[outer_loop][2], AESMOD, 8)) ^ (three.gf_multiply_modular(initializationVector[outer_loop][3], AESMOD, 8)) ^ initializationVector[outer_loop][0] ^ initializationVector[outer_loop][1], (two.gf_multiply_modular(initializationVector[outer_loop][3], AESMOD, 8)) ^ (three.gf_multiply_modular(initializationVector[outer_loop][0], AESMOD, 8)) ^ initializationVector[outer_loop][1] ^ initializationVector[outer_loop][2]
        initializationVector[outer_loop][0], initializationVector[outer_loop][1], initializationVector[outer_loop][2], initializationVector[outer_loop][3] = temp0, temp1, temp2, temp3


def invMixColumns(initializationVector):
    zeroDict = {0: BitVector(bitstring='00001110'), 1: BitVector(bitstring='00001011'),
                2: BitVector(bitstring='00001101'), 3: BitVector(bitstring='00001001')}
    for outer_loop in range(0, 4, 1):
        temp0 = (zeroDict[0].gf_multiply_modular(initializationVector[outer_loop][0], AESMOD, 8))
        temp1 = (zeroDict[0].gf_multiply_modular(initializationVector[outer_loop][1], AESMOD, 8))
        temp2 = (zeroDict[0].gf_multiply_modular(initializationVector[outer_loop][2], AESMOD, 8))
        temp3 = (zeroDict[0].gf_multiply_modular(initializationVector[outer_loop][3], AESMOD, 8))
        for inner_loop in range(1, 4):
            temp0 ^= (zeroDict[inner_loop].gf_multiply_modular(initializationVector[outer_loop][inner_loop], AESMOD, 8))
            temp1 ^= (zeroDict[inner_loop].gf_multiply_modular(initializationVector[outer_loop][(inner_loop + 1) % 4], AESMOD, 8))
            temp2 ^= (zeroDict[inner_loop].gf_multiply_modular(initializationVector[outer_loop][(inner_loop + 2) % 4], AESMOD, 8))
            temp3 ^= (zeroDict[inner_loop].gf_multiply_modular(initializationVector[outer_loop][(inner_loop + 3) % 4], AESMOD, 8))
        initializationVector[outer_loop][0], initializationVector[outer_loop][1], initializationVector[outer_loop][2], initializationVector[outer_loop][3] = temp0, temp1, temp2, temp3


def addRoundKey(initializationVector, keyWords, round_num, op):
    for outer_loop in range(0, 4, 1):
        for inner_loop in range(0, 4, 1):
            initializationVector[outer_loop][inner_loop] ^= keyWords[(4 * op(round_num, 1)) + outer_loop][8 * inner_loop:8 + (8 * inner_loop)]


def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for outer_loop in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=outer_loop, size=8).gf_MI(AESMOD, 8) if outer_loop != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for idx in range(0, 4, 1)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=outer_loop, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for idx in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AESMOD, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the KEY schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the KEY
    #  schedule. We will store all 60 keywords in the following list:
    keyWords = [None for outer_loop in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for outer_loop in range(8):
        keyWords[outer_loop] = key_bv[outer_loop*32 : outer_loop*32 + 32]
    for outer_loop in range(8,60):
        if outer_loop%8 == 0:
            kwd, round_constant = gee(keyWords[outer_loop-1], round_constant, byte_sub_table)
            keyWords[outer_loop] = keyWords[outer_loop-8] ^ kwd
        elif (outer_loop - (outer_loop//8)*8) < 4:
            keyWords[outer_loop] = keyWords[outer_loop-8] ^ keyWords[outer_loop-1]
        elif (outer_loop - (outer_loop//8)*8) == 4:
            keyWords[outer_loop] = BitVector(size = 0)
            for inner_loop in range(0, 4, 1):
                keyWords[outer_loop] += BitVector(intVal =
                                 byte_sub_table[keyWords[outer_loop-1][8*inner_loop:8*inner_loop+8].intValue()], size = 8)
            keyWords[outer_loop] ^= keyWords[outer_loop-8]
        elif ((outer_loop - (outer_loop//8)*8) > 4) and ((outer_loop - (outer_loop//8)*8) < 8):
            keyWords[outer_loop] = keyWords[outer_loop-8] ^ keyWords[outer_loop-1]
        else:
            sys.exit("error in KEY scheduling algo for outer_loop = %d" % outer_loop)
    return keyWords


def gee(keyword, round_num_constant, byte_sub_table):
    rotWord = keyword.deep_copy()
    rotWord << 8
    word = BitVector(size=0)
    for outer_loop in range(0, 4, 1):
        word += BitVector(intVal=byte_sub_table[rotWord[8 * outer_loop:8 * outer_loop + 8].intValue()], size=8)
    word[:8] ^= round_num_constant
    round_num_constant = round_num_constant.gf_multiply_modular(BitVector(intVal=0x02), AESMOD, 8)
    return word, round_num_constant


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for outer_loop in range(0, 256):
        a = BitVector(intVal=outer_loop, size=8).gf_MI(AESMOD, 8) if outer_loop != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for idx in range(0, 4, 1)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def encrypt(INFILE, OUTFILE, KEY):
    with open(OUTFILE, 'wb') as FILEOUT:
        with open('encrypted_hex.txt', 'w') as HEXFILE:
            keyWords = gen_key_schedule_256(KEY)
            bv = BitVector(filename=INFILE)
            initializationVector = [[0 for idx in range(0, 4, 1)] for idx in range(0, 4, 1)]
            tShift = [0] * 4
            while bv.more_to_read:
                bitvec = bv.read_bits_from_file(128)
                if len(bitvec) > 0:
                    if len(bitvec) != 128:
                        bitvec.pad_from_right(128 - len(bitvec))

                    # Filling in initializationVector and XORing
                    for outer_loop in range(0, 4, 1):
                        for inner_loop in range(0, 4, 1):
                            initializationVector[outer_loop][inner_loop] = bitvec[32 * outer_loop + 8 * inner_loop:32 * outer_loop + 8 * (inner_loop + 1)] ^ keyWords[outer_loop][8 * inner_loop:8 + (8 * inner_loop)]

                    for round_num in range(14):
                        # SubBytes
                        subBytes(initializationVector, subBytesTable)
                        # ShiftRows
                        shiftRows(tShift, initializationVector, operator.sub)
                        # ColumnMixing
                        if round_num is not 13:
                            two_times = BitVector(bitstring='00000010')
                            three_times = BitVector(bitstring='00000011')
                            mixColumns(initializationVector, two_times, three_times)
                        # Add round_num Key
                        addRoundKey(initializationVector, keyWords, round_num, operator.add)

                    for outer_loop in range(0, 4, 1):
                        for inner_loop in range(0, 4, 1):
                            initializationVector[outer_loop][inner_loop].write_to_file(FILEOUT)
                            HEXFILE.write(initializationVector[outer_loop][inner_loop].get_bitvector_in_hex())


def decrypt(INFILE, OUTFILE, KEY):
    with open(OUTFILE, 'wb') as FILEOUT:
        tShift = [0] * 4
        keyWords = gen_key_schedule_256(KEY)
        bv = BitVector(filename=INFILE)
        initializationVector = [[0 for idx in range(0, 4, 1)] for idx in range(0, 4, 1)]
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) != 128:
                    bitvec.pad_from_right(128 - len(bitvec))
                # Filling in initializationVector and XORing
                for outer_loop in range(0, 4, 1):
                    for inner_loop in range(0, 4, 1):
                        initializationVector[outer_loop][inner_loop] = bitvec[32 * outer_loop + 8 * inner_loop:32 * outer_loop + 8 * (inner_loop + 1)] ^ keyWords[-(4 - outer_loop)][8 * inner_loop:8 + (8 * inner_loop)]
                for round_num in range(14, 0, -1):
                    # Inverse shift rows
                    shiftRows(tShift, initializationVector, operator.add)
                    # Inverse SubBytes
                    subBytes(initializationVector, invSubBytesTable)
                    # Add round_num Key
                    addRoundKey(initializationVector, keyWords, round_num, operator.sub)
                    # Inverse ColumnMixing
                    if round_num is not 1:
                        invMixColumns(initializationVector)
                for outer_loop in range(0, 4, 1):
                    for inner_loop in range(0, 4, 1):
                        initializationVector[outer_loop][inner_loop].write_to_file(FILEOUT)


if __name__ == '__main__':
    if path.isfile("key.txt") is False or path.isfile("message.txt") is False:
        exit(1)
    subBytesTable, invSubBytesTable = genTables()
    with open("key.txt", 'r') as KEYGEN:
        KEY = BitVector(textstring=KEYGEN.readline().strip())
        encrypt('message.txt', 'encrypted.txt', KEY)
        decrypt('encrypted.txt', 'decrypted.txt', KEY)
    remove("encrypted.txt")
    rename("encrypted_hex.txt", "encrypted.txt")
    exit(0)
