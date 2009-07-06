// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HTTP_H
#define HTTP_H

#include "connection.h"


class EString;
class Command;
class Mailbox;
class Address;
class EStringList;


class HTTP: public Connection {
public:
    HTTP( int s );

    void react( Event e );

    enum State {
        Request, Header, Body, Parsed, Done
    };
    State state() const;
    void parseRequest( EString );
    void parseHeader( const EString & );
    void parseParameters();

    class UString parameter( const EString & ) const;

    class User * user() const;

    class HttpSession * session() const;
    void setSession( HttpSession * );

    EString hostHeader() const;

    EString body() const;

    void process();

    uint status() const;
    void setStatus( uint, const EString & );
    void addHeader( const EString & );

    void respond( const EString &, const EString & );

private:
    void parseAccept( const EString &, uint );
    void parseAcceptCharset( const EString &, uint );
    void parseAcceptEncoding( const EString &, uint );
    void parseConnection( const EString & );
    void parseHost( const EString & );
    void parseIfMatch( const EString & );
    void parseIfModifiedSince( const EString & );
    void parseIfNoneMatch( const EString & );
    void parseIfUnmodifiedSince( const EString & );
    void parseReferer( const EString & );
    void parseTransferEncoding( const EString & );
    void parseUserAgent( const EString & );
    void parseCookie( const EString & );
    void parseContentLength( const EString & );

    void parseList( const EString &, const EString & );
    void parseListItem( const EString &, const EString &, uint );
    void skipValues( const EString &, uint &, uint & );
    void expect( const EString & value, uint &, char );
    bool isTokenChar( char );

    bool canReadHTTPLine() const;
    EString line();

    void clear();

private:
    class HTTPData * d;
};


class HTTPS
    : public HTTP
{
public:
    HTTPS( int );

    void finish();

private:
    class HTTPSData * d;
};


#endif
