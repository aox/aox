#ifndef BYTEFORWARDER_H
#define BYTEFORWARDER_H

#include "connection.h"


class ByteForwarder: public Connection
{
public:
    ByteForwarder( int );

    void react( Event );

    void setSibling( ByteForwarder * );

private:
    class ByteForwarder * s;
};

#endif
