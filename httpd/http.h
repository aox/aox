// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTTP_H
#define HTTP_H

#include "connection.h"


class String;
class Command;
class Mailbox;
class Address;


class HTTP : public Connection {
public:
    HTTP( int s );

    void react( Event e );

private:
    void parse();

    void parseRequest();
    void parseHeader();
    void respond();

    void parseAccept( const String & );
    void parseAcceptCharset( const String & );
    void parseAcceptEncoding( const String & );
    void parseCacheControl( const String & );
    void parseConnection( const String & );
    void parseHost( const String & );
    void parseIfMatch( const String & );
    void parseIfModifiedSince( const String & );
    void parseIfNoneMatch( const String & );
    void parseIfUnmodifiedSince( const String & );
    void parseReferer( const String & );
    void parseTransferEncoding( const String & );
    void parseUserAgent( const String & );
    void parseVary( const String & );

    bool canReadHTTPLine() const;
    String line();

    void error( const String & );
    void clear();
    void addHeader( const String & );

    String page() const;

private:
    class HTTPData * d;
};


#endif
