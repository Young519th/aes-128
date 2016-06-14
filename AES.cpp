//
//  AES.cpp
//  AES_CBC
//
//  Created by Young on 6/12/16.
//  Copyright © 2016 杨言. All rights reserved.
//

#include "AES.h"
#include <iostream>
using namespace std;

int AES::findFirstBit(unsigned short a)
{
    //find first bit which is 1
    int high = -1;
    for (int i = 0 ; i < 16 ; i ++)
    {
        if ((a & (1 << i)) != 0)
            high = i;
    }
    return high;
}

unsigned short AES::moduleGFE(unsigned short a, unsigned short b, unsigned short& result)
{
    //% in GF field for euclid
    unsigned short r = 0;
    while (findFirstBit(a) >= findFirstBit(b))
    {
        r = r + (1 << (findFirstBit(a) - findFirstBit(b)));
        a = a ^ (b << (findFirstBit(a) - findFirstBit(b)));
    }
    result = r;
    return a;
}

unsigned short AES::timeGFE(unsigned short a, unsigned short b)
{
    //* in GF field for euclid (not consider carrying)
    unsigned short r = 0;
    while (findFirstBit(a) >= 0)
    {
        r = r ^ (b << (findFirstBit(a)));
        a = a ^ (1 << findFirstBit(a));
    }
    return r;
}

unsigned char AES::timeGF(unsigned char a, unsigned char b)
{
    //* in GF field in normal (consider carrying in 2^8)
    unsigned char r = 0;
    unsigned char current = b;
    int high = findFirstBit(a);
    for (int i = 0 ; i <= high ; i ++)
    {
        if (i > 0)
        {
            if ((current & (1 << 7)) == 0)
                current = current << 1;
            else
            {
                current = current << 1;
                current = current ^ (unsigned char)27;
            }
        }
        if ((a & (1 << i)) != 0)
        {
            r = r ^ current;
        }
    }
    return r;
}

unsigned char AES::findReverse(unsigned char a)
{
    //b is 100011011
    unsigned short x1, x2, x3;
    unsigned short y1, y2, y3;
    unsigned short t1, t2, t3;
    if (a == 0)
    {
        return 0;
    }
    x1 = 1; x2 = 0; x3 = a;
    y1 = 0; y2 = 1; y3 = 283;
    unsigned short k;
    for (t3 = moduleGFE(x3, y3, k); t3 != 0; t3 = moduleGFE(x3, y3, k))
    {
        t1 = x1 ^ timeGFE(k, y1);
        t2 = x2 ^ timeGFE(k, y2);
        x1 = y1;
        x2 = y2;
        x3 = y3;
        y1 = t1;
        y2 = t2;
        y3 = t3;
    }
    if (y3 == 1)
        return y1;
    else
        return 0;
}

unsigned char AES::subByte(unsigned char a)
{
    unsigned char b = findReverse(a);
    unsigned char r = 0;
    for (int i = 0 ; i < 8 ; i ++)
    {
        bool temp = false;
        for (int j = 0 ; j < 8 ; j ++)
        {
            if (((s[i] & (1 << (7 - j))) != 0) && ((b & (1 << j)) != 0))
                temp = !temp;
        }
        if (temp)
            r = r ^ (1 << i);
    }
    unsigned char t = 99;
    r = r ^ t;
    return r;
}

void AES::subWord(unsigned char* word)
{
    for (int i = 0 ; i < 4 ; i ++)
    {
        word[i] = subByte(word[i]);
    }
}

void AES::rotWord(unsigned char* word)
{
    unsigned char tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void AES::generateRoundKey()
{
    //allocate space
    w = new unsigned char* [4 * round + 4];
    for (int i = 0 ; i < 4 * round + 4; i ++)
    {
        w[i] = new unsigned char[4];
    }
    //0-3 round
    for (int i = 0 ; i <= 3 ; i ++)
        for (int j = 0 ; j < 4 ; j ++)
        {
            w[i][j] = key[4 * j + i];
        }
    //4-43 round
    for (int i = 4 ; i < 4 * round + 4 ; i ++)
    {
        unsigned char* temp = new unsigned char[4];
        for (int j = 0 ; j < 4 ; j ++)
        {
            temp[j] = w[i - 1][j];
        }
        if (i % 4 == 0)
        {
            rotWord(temp);
            subWord(temp);
            for (int j = 0 ; j < 4 ; j ++)
            {
                temp[j] = temp[j] ^ rcon[i / 4 - 1][j];
            }
        }
        for (int j = 0 ; j < 4 ; j ++)
        {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
        delete[] temp;
    }
}

void AES::initAES()
{
    //to allocate the original value for AES
    //the 4 * 4 matrix is put by column first and row next
    for (int i = 0 ; i < 16 ; i ++)
        key[i] = 0;
    key[12] = key[13] = key[14] = key[15] = 1;
    round = 10;
    s = new unsigned char[8];
    s[0] = 143;
    s[1] = 199;
    s[2] = 227;
    s[3] = 241;
    s[4] = 248;
    s[5] = 124;
    s[6] = 62;
    s[7] = 31;
    rcon = new unsigned char*[round];
    for (int i = 0 ; i < 10 ; i ++)
    {
        rcon[i] = new unsigned char[4];
        rcon[i][1] = rcon[i][2] = rcon[i][3] = 0;
    }
    for (int i = 0 ; i < 8 ; i ++)
    {
        rcon[i][0] = (1 << i);
    }
    rcon[8][0] = 27;
    rcon[9][0] = 54;
    a[0] = 2;
    a[1] = 1;
    a[2] = 1;
    a[3] = 3;
    message = 0;
    cipher = 0;
}

void AES::addRoundKey(unsigned char** s, int round)
{
    for (int j = 0 ; j < 4 ; j ++)
        for (int i = 0 ; i < 4 ; i ++)
        {
            s[i][j] = s[i][j] ^ w[4 * round + j][i];
        }
}

void AES::subBytes(unsigned char** s)
{
    for (int i = 0 ; i < 4 ; i ++)
        for (int j = 0 ; j < 4 ; j ++)
        {
            s[i][j] = subByte(s[i][j]);
        }
}

void AES::shiftRows(unsigned char** s)
{
    unsigned char tmp;
    tmp = s[1][0];
    s[1][0] = s[1][1];
    s[1][1] = s[1][2];
    s[1][2] = s[1][3];
    s[1][3] = tmp;
    tmp = s[2][0];
    s[2][0] = s[2][2];
    s[2][2] = tmp;
    tmp = s[2][1];
    s[2][1] = s[2][3];
    s[2][3] = tmp;
    tmp = s[3][0];
    s[3][0] = s[3][3];
    s[3][3] = s[3][2];
    s[3][2] = s[3][1];
    s[3][1] = tmp;
}

void AES::mixColumns(unsigned char** s)
{
    unsigned char d[4];
    for (int j = 0 ; j < 4 ; j ++)
    {
        d[0] = timeGF(a[0], s[0][j]) ^ timeGF(a[3], s[1][j]) ^ timeGF(a[2], s[2][j]) ^ timeGF(a[1], s[3][j]);
        d[1] = timeGF(a[1], s[0][j]) ^ timeGF(a[0], s[1][j]) ^ timeGF(a[3], s[2][j]) ^ timeGF(a[2], s[3][j]);
        d[2] = timeGF(a[2], s[0][j]) ^ timeGF(a[1], s[1][j]) ^ timeGF(a[0], s[2][j]) ^ timeGF(a[3], s[3][j]);
        d[3] = timeGF(a[3], s[0][j]) ^ timeGF(a[2], s[1][j]) ^ timeGF(a[1], s[2][j]) ^ timeGF(a[0], s[3][j]);
        s[0][j] = d[0];
        s[1][j] = d[1];
        s[2][j] = d[2];
        s[3][j] = d[3];
    }
}

void AES::encryptAES(unsigned char** m)
{
    //m is asked to have a size of 4 * 4
    message = m;
    unsigned char** state = new unsigned char*[4];
    for (int i = 0 ; i < 4 ; i ++)
    {
        state[i] = new unsigned char[4];
        for (int j = 0 ; j < 4 ; j ++)
        {
            state[i][j] = m[i][j];
        }
    }
    addRoundKey(state, 0);
    for (int i = 1 ; i < round ; i ++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, i);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, round);
    if (cipher != 0)
    {
        for (int i = 0 ; i < 4 ; i ++)
            delete[] cipher[i];
        delete[] cipher;
        cipher = 0;
    }
    cipher = state;
}

void AES::output()
{
    //to print the AES's message and cipher
    cout << "message:" << endl;
    for (int i = 0 ; i < 4 ; i ++)
    {
        for (int j = 0 ; j < 4 ; j ++)
        {
            cout << (int)message[i][j] << " ";
        }
        cout << endl;
    }
    cout << "--------" << endl;
    cout << "cipher:" << endl;
    for (int i = 0 ; i < 4 ; i ++)
    {
        for (int j = 0 ; j < 4 ; j ++)
        {
            cout << (int)cipher[i][j] << " ";
        }
        cout << endl;
    }
}

unsigned char** AES::getCipher()
{
    if (cipher != 0)
        return cipher;
    else
        return 0;
}