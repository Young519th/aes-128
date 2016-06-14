//
//  AES_CBC.cpp
//  AES_CBC
//
//  Created by Young on 6/13/16.
//  Copyright © 2016 杨言. All rights reserved.
//

#include "AES_CBC.h"
#include <iostream>
#include <string>
#include <sstream>
using namespace std;

void AES_CBC::padding()
{
    //use PKCS7 for padding
    int range = realBytes / 16;
    paddingBytes = (range + 1) * 16 - realBytes;
    if (realBytes < 16)
        paddingBytes += 16;
    for (int i = realBytes ; i < realBytes + paddingBytes; i ++)
    {
        message[i] = (unsigned char)paddingBytes;
    }
}

void AES_CBC::CBC()
{
    unsigned char** cipher = 0;
    unsigned char** plain = 0;
    plain = new unsigned char*[4];
    for (int i = 0 ; i < 4 ; i ++)
    {
        plain[i] = new unsigned char[4];
        for (int j = 0 ; j < 4 ; j ++)
            plain[i][j] = IV[i][j];
    }
    for (int k = 0 ; k < (realBytes + paddingBytes) / 16 ; k ++)
    {
        for (int j = 0 ; j < 4 ; j ++)
            for (int i = 0 ; i < 4 ; i ++)
            {
                plain[i][j] = plain[i][j] ^ message[16 * k + 4 * j + i];
            }
        aes.encryptAES(plain);
        cipher = aes.getCipher();
        cout << "--------" << endl;
        cout << "cipher[" << k << "]:" << endl;
        for (int i = 0 ; i < 4 ; i ++)
        {
            for (int j = 0 ; j < 4 ; j ++)
            {
                plain[i][j] = cipher[i][j];
                cout << (int)plain[i][j] << " ";
            }
            cout << endl;
        }
    }
    for (int i = 0 ; i < 4 ; i ++)
        delete[] plain[i];
    delete[] plain;
}

void AES_CBC::encryptAES_CBC()
{
    string buff;
    cout << "Please input the message that you want to encrypt by ASCII splited by space:" << endl;
    getline(cin, buff);
    istringstream istr(buff);
    int asc;
    bool normal = false;
    while (istr >> asc)
    {
        normal = true;
        if (asc < 0 || asc > 255)
        {
            cout << "ASCII is over range!" << endl;
            normal = false;
            break;
        }
        message[realBytes++] = (unsigned char)asc;
        if(realBytes >= maxBytes)
            break;
    }
    if (normal)
    {
        padding();
        cout << "Padding finished!" << endl;
        for (int i = 0 ; i < realBytes + paddingBytes; i ++)
        {
            cout << (int)message[i] << " ";
        }
        cout << endl;
        CBC();
    }
}