#ifndef BUFFER_H
#define BUFFER_H

#include "global.h"

class Arena;
class String;


class Buffer {
public:
    Buffer();
    ~Buffer();

    void append( const String & );
    void append( const char *, uint = 0 );

    void read( int );
    void write( int );

    bool eof() const;
    uint size() const;
    void remove( uint );
    char operator[]( uint ) const;
    String * string( uint ) const;
    String * removeLine();

    Arena * arena() const;

private:
    class BufferData *d;
};


#endif
