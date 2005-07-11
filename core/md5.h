// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MD5_H
#define MD5_H

#include "global.h"


class String;
class Buffer;


class MD5
    : public Garbage
{
public:
    MD5();

    void add( const char *, uint );
    void add( const String & );

    String hash();
    static String hash( const String & );
    static String hash( const Buffer & );
    static String HMAC( const String &, const String & );

private:
    bool finalised;
    uint32 bits[2];
    uint32 buf[4];
    char in[64];

    void init();
    void transform();
};


#endif
