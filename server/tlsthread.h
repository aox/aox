// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TLSTHREAD_H
#define TLSTHREAD_H

#include "global.h"


class TlsThread
    : public Garbage
{
public:
    TlsThread();
    ~TlsThread();

    static void setup();

    void setServerFD( int );
    void setClientFD( int );

    void start();

    bool broken() const;

    bool sslErrorSeriousness( int );

private:
    class TlsThreadData * d;
};

#endif
