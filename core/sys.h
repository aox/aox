// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SYS_H
#define SYS_H


// Add a declaration to this file when all of the following are true:
//   1. We need that function in several places.
//   2. We don't want to include the system header file.
//   3. The function is reasonably portable.


extern "C" {
    void exit( int );
    unsigned int strlen( const char * );
    void *memmove( void *, const void *, unsigned int );
    int memcmp( const void *, const void *, unsigned int );
    void memset( void *, int, unsigned int );
    void bzero( void *, unsigned int );
    void *malloc( uint );
    void free( void * );
}


#endif
