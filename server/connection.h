// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONNECTION_H
#define CONNECTION_H

#include "log.h"
#include "endpoint.h"

class Buffer;
class TlsServer;


class Connection
    : public Garbage
{
public:
    enum Type {
        Client,
        DatabaseClient,
        ImapServer,
        LogServer,
        LogClient,
        OryxServer,
        OryxClient,
        OryxConsole,
        SmtpServer,
        SmtpClient,
        Pop3Server,
        HttpServer,
        TlsProxy,
        TlsClient,
        RecorderClient,
        RecorderServer,
        Listener,
        Pipe,
        ManageSieveServer
    };
    Connection();
    Connection( int, Type );
    virtual ~Connection();

    enum State { Invalid,
                 Inactive,
                 Listening, Connecting, Connected, Closing };
    void setState( Connection::State );
    State state() const;
    bool active() const;
    bool valid() const;

    int fd() const;
    uint timeout() const;
    void setTimeout( uint );
    void setTimeoutAfter( uint );
    void extendTimeout( uint );
    void setBlocking( bool );

    Buffer * writeBuffer() const;
    Buffer * readBuffer() const;
    Endpoint self() const;
    Endpoint peer() const;
    void setType( Type );
    Type type() const;
    virtual String description() const;

    void startTls( TlsServer * );
    bool hasTls() const;

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

    Log * log() const;
    void log( const String &, Log::Severity = Log::Info );
    void commit( Log::Severity = Log::Info );

private:
    class ConnectionData *d;
    void init( int );
};


#endif
