//
//  AES_CTR.h
//  AES_CTR
//
//  Created by Young on 6/14/16.
//  Copyright © 2016 杨言. All rights reserved.
//

#ifndef AES_CTR_h
#define AES_CTR_h

#include "AES.h"

class AES_CTR
{
private:
    AES aes;
    unsigned char* message;
    int maxBytes;
    int realBytes;
    int paddingBytes;
    unsigned char* counter;
    void padding();
    void CTR();
    void moveCounter();
public:
    AES_CTR()
    {
        maxBytes = 1024;
        message = new unsigned char[maxBytes + 16];
        realBytes = 0;
        paddingBytes = 0;
        counter = new unsigned char[16];
        for (int i = 0 ; i < 16 ; i ++)
            counter[i] = 0;
    }
    ~AES_CTR()
    {
        delete[] message;
        delete[] counter;
    }
    void encryptAES_CTR();
};

#endif /* AES_CTR_h */
