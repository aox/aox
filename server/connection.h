// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONNECTION_H
#define CONNECTION_H

#include "log.h"
#include "endpoint.h"

class User;
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
        GraphDumper,
        SmtpServer,
        SmtpClient,
        Pop3Server,
        HttpServer,
        TlsProxy,
        TlsClient,
        RecorderClient,
        RecorderServer,
        EGDServer,
        Listener,
        Pipe,
        ManageSieveServer,
        LdapRelay
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

    virtual void close();
    virtual void read();
    virtual void write();
    virtual bool canRead();
    virtual bool canWrite();

    void enqueue( const String & );

    enum Event { Error, Connect, Read, Timeout, Close, Shutdown };
    virtual void react( Event ) = 0;

    bool isPending( Event );

    int listen( const Endpoint &, bool );
    int connect( const Endpoint & );
    int connect( const String &, uint );
    int accept();
    static void setAny6ListensTo4( bool );
    static bool any6ListensTo4();

    static int socket( Endpoint::Protocol );

    Log * log() const;
    void log( const String &, Log::Severity = Log::Info );

    bool accessPermitted() const;

    enum Property {
        Listens = 1,
        Internal = 2,
        StartsSSL = 4
    };

    bool hasProperty( Property ) const;

protected:
    void substitute( Connection *, Event );
    void init( int );

private:
    class ConnectionData *d;
};


#endif
