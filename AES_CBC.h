//
//  AES_CBC.h
//  AES_CBC
//
//  Created by Young on 6/13/16.
//  Copyright © 2016 杨言. All rights reserved.
//

#ifndef AES_CBC_h
#define AES_CBC_h

#include "AES.h"

class AES_CBC
{
private:
    AES aes;
    unsigned char* message;
    unsigned char** IV;
    int maxBytes;
    int realBytes;
    int paddingBytes;
    void padding();
    void CBC();
public:
    AES_CBC()
    {
        IV = new unsigned char*[4];
        for (int i = 0 ; i < 4 ; i ++)
        {
            IV[i] = new unsigned char[4];
            for (int j = 0 ; j < 4 ; j ++)
                IV[i][j] = 0;
        }
        maxBytes = 1024;
        message = new unsigned char[maxBytes + 16];
        realBytes = 0;
        paddingBytes = 0;
    }
    ~AES_CBC()
    {
        delete[] message;
        for (int i = 0 ; i < 4 ; i ++)
            delete[] IV[i];
        delete[] IV;
    }
    void encryptAES_CBC();
};

#endif /* AES_CBC_h */
