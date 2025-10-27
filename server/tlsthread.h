// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef TLSTHREAD_H
#define TLSTHREAD_H

#include "global.h"


class TlsThread
    : public Garbage
{
public:
    TlsThread( bool = false );
    ~TlsThread();

    static void setup();

    void setServerFD( int );
    void setClientFD( int );

    void start();

    bool broken() const;

    void shutdown();
    bool isShuttingDown() const;

    bool sslErrorSeriousness( int );
    
    void close();

private:
    class TlsThreadData * d;
};

#endif
