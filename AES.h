//
//  AES.h
//  AES_CBC
//
//  Created by Young on 6/12/16.
//  Copyright © 2016 杨言. All rights reserved.
//

#ifndef AES_h
#define AES_h

class AES //the AES-128
{
private:
    unsigned char key[16]; //the key
    int round; //the numbers of rounds
    unsigned char* s; //to generate next round key
    unsigned char** rcon; //the round constants
    unsigned char** w;
    unsigned char a[4];
    unsigned char** message;
    unsigned char** cipher;
    void initAES();
    void generateRoundKey();
    int findFirstBit(unsigned short);
    unsigned short moduleGFE(unsigned short, unsigned short, unsigned short&);
    unsigned short timeGFE(unsigned short, unsigned short);
    unsigned char timeGF(unsigned char, unsigned char);
    unsigned char findReverse(unsigned char);
    unsigned char subByte(unsigned char);
    void subWord(unsigned char*);
    void rotWord(unsigned char*);
    void addRoundKey(unsigned char**, int);
    void subBytes(unsigned char**);
    void shiftRows(unsigned char**);
    void mixColumns(unsigned char**);
public:
    AES()
    {
        initAES();
        generateRoundKey();
    }
    ~AES()
    {
        delete[] s;
        for (int i = 0 ; i < round; i ++)
        {
            delete[] rcon[i];
        }
        delete[] rcon;
        for (int i = 0 ; i < 4 * round + 4; i ++)
        {
            delete[] w[i];
        }
        delete[] w;
    }
    void encryptAES(unsigned char**);
    void output();
    unsigned char** getCipher();
};

#endif /* AES_h */
