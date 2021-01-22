//TODO add copyright statement

#ifndef _OSCORE_TEST_VECTORS_H
#define _OSCORE_TEST_VECTORS_H

/*
 C.1.1. Client

Inputs:

    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Master Salt: 0x9e7ca92223786340 (8 bytes)
    Sender ID: 0x (0 byte)
    Recipient ID: 0x01 (1 byte)

From the previous parameters,

    info (for Sender Key): 0x8540f60a634b657910 (9 bytes)
    info (for Recipient Key): 0x854101f60a634b657910 (10 bytes)
    info (for Common IV): 0x8540f60a6249560d (8 bytes)

Outputs:

    Sender Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    Recipient Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)

C.1.2. Server

Inputs:

    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Master Salt: 0x9e7ca92223786340 (8 bytes)
    Sender ID: 0x01 (1 byte)
    Recipient ID: 0x (0 byte)

From the previous parameters,

    info (for Sender Key): 0x854101f60a634b657910 (10 bytes)
    info (for Recipient Key): 0x8540f60a634b657910 (9 bytes)
    info (for Common IV): 0x8540f60a6249560d (8 bytes)

Outputs:

    Sender Key: 0xffb14e093c94c9cac9471648b4f98710 (16 bytes)
    Recipient Key: 0xf0910ed7295e6ad4b54fc793154302ff (16 bytes)
    Common IV: 0x4622d4dd6d944168eefb54987c (13 bytes)

 C.2. Test Vector 2: Key Derivation without Master Salt

In this test vector, the default values are used for AEAD Algorithm, KDF, and Master Salt.
C.2.1. Client

Inputs:

    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Sender ID: 0x00 (1 byte)
    Recipient ID: 0x01 (1 byte)

From the previous parameters,

    info (for Sender Key): 0x854100f60a634b657910 (10 bytes)
    info (for Recipient Key): 0x854101f60a634b657910 (10 bytes)
    info (for Common IV): 0x8540f60a6249560d (8 bytes)

Outputs:

    Sender Key: 0x321b26943253c7ffb6003b0b64d74041 (16 bytes)
    Recipient Key: 0xe57b5635815177cd679ab4bcec9d7dda (16 bytes)
    Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes)

C.2.2. Server

Inputs:

    Master Secret: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
    Sender ID: 0x01 (1 byte)
    Recipient ID: 0x00 (1 byte)

From the previous parameters,

    info (for Sender Key): 0x854101f60a634b657910 (10 bytes)
    info (for Recipient Key): 0x854100f60a634b657910 (10 bytes)
    info (for Common IV): 0x8540f60a6249560d (8 bytes)

Outputs:

    Sender Key: 0xe57b5635815177cd679ab4bcec9d7dda (16 bytes)
    Recipient Key: 0x321b26943253c7ffb6003b0b64d74041 (16 bytes)
    Common IV: 0xbe35ae297d2dace910c52e99f9 (13 bytes)


*/


uint8_t master_secret[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
int 	master_secret_len = 16;

uint8_t master_secret_2[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
int 	master_secret_2_len = 16;


uint8_t master_salt[8] = { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
int 	master_salt_len = 8;

uint8_t sender_id[] = {};
int	sender_id_len = 0;

uint8_t sender_id_2[1] = { 0x00 };
uint8_t sender_id_2_len = 1;

uint8_t recipient_id[1] = { 0x01 };
int 	recipient_id_len = 1;

uint8_t client_sender_key[16] = { 0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff  };   
uint8_t client_recipient_key[16] = { 0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10 };
int 	key_len = 16;

uint8_t client_common_iv[13] =  { 0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c };
int 	iv_len = 13;

uint8_t client_sender_key_no_salt[16] = { 0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff, 0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41 };

uint8_t client_recipient_key_no_salt[16] = { 0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd, 0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda };

uint8_t client_common_iv_no_salt[13] = { 0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9, 0x10, 0xc5, 0x2e, 0x99, 0xf9 };

#endif /* !_OSCORE_TEST_VECTORS_H */
