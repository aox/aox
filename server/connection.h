#ifndef CONNECTION_H
#define CONNECTION_H

#include "endpoint.h"

class Buffer;


class Connection {
public:
    Connection();
    Connection( int );
    virtual ~Connection();

    enum State { Invalid, Inactive, Listening, Connecting, Connected, Closing };
    void setState( State );
    State state() const;
    bool active() const;
    bool valid() const;

    int fd() const;
    int timeout() const;
    void setTimeout( int );
    void setBlocking( bool );

    Buffer * writeBuffer() const;
    Buffer * readBuffer() const;
    class Arena * arena() const;
    Endpoint self();
    Endpoint peer();

    void startTLS();
    bool hasTLS() const;

    void close();
    virtual void read();
    virtual void write();
    virtual bool canRead();
    virtual bool canWrite();

    void enqueue( const String & );
    
    enum Event { Error, Connect, Read, Timeout, Close, Shutdown };
    virtual void react( Event ) = 0;

    bool isPending( Event );

    int listen( const Endpoint & );
    int connect( const Endpoint & );
    int accept();

    static int socket( Endpoint::Protocol );

    bool operator <=( const Connection &b ) {
        return fd() <= b.fd();
    }

private:
    class ConnectionData *d;
    void init( int );
};


#endif
