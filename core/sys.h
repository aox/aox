// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SYS_H
#define SYS_H

extern "C" {
    void exit( int );
    unsigned int strlen( const char * );
    void *memmove( void *, const void *, unsigned int );
    int memcmp( const void *, const void *, unsigned int );
    void memset( void *, int, unsigned int );
    void bzero( void *, unsigned int );
}

#endif
