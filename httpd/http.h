// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTTP_H
#define HTTP_H

#include "connection.h"


class String;
class Command;
class Mailbox;
class Address;
class StringList;


class HTTP: public Connection {
public:
    HTTP( int s );

    void react( Event e );

    enum State {
        Request, Header, Done
    };
    State state() const;
    void parse();
    void parseRequest( String );
    void parseHeader( const String & );
    void respond();
    StringList * response();

private:
    void parseAccept( const String &, uint );
    void parseAcceptCharset( const String &, uint );
    void parseAcceptEncoding( const String &, uint );
    void parseConnection( const String & );
    void parseHost( const String & );
    void parseIfMatch( const String & );
    void parseIfModifiedSince( const String & );
    void parseIfNoneMatch( const String & );
    void parseIfUnmodifiedSince( const String & );
    void parseReferer( const String & );
    void parseTransferEncoding( const String & );
    void parseUserAgent( const String & );

    void parseList( const String &, const String & );
    void parseListItem( const String &, const String &, uint );
    void skipValues( const String &, uint &, uint & );
    void expect( const String & value, uint &, char );
    bool isTokenChar( char );

    bool canReadHTTPLine() const;
    String line();

    void error( const String & );
    void clear();
    void addHeader( const String & );

    String page();

private:
    class HTTPData * d;
};


#endif
