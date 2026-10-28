// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HTTP_H
#define HTTP_H

#include "connection.h"


class EString;


class HTTP
    : public Connection
{
public:
    HTTP( int );

    void react( Event );

    enum State {
        Request, Header, Body, Parsed
    };
    State state() const;

    EString method() const;
    EString path() const;
    EString body() const;
    EString hostHeader() const;
    EString header( const EString & ) const;

    uint status() const;
    void setStatus( uint, const EString & );
    void addHeader( const EString & );
    void respond( const EString &, const EString & );

protected:
    virtual void handle();

private:
    void parse();
    void parseRequest( const EString & );
    void parseHeader( const EString & );
    void parseHost( const EString & );
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
};


#endif
