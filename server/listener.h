// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTENER_H
#define LISTENER_H

#include "connection.h"
#include "configuration.h"
#include "string.h"
#include "loop.h"
#include "log.h"


template< class T >
class Listener
    : public Connection
{
public:
    Listener( const Endpoint &e, const String & s )
        : Connection(), svc( s )
    {
        setType( Connection::Listener );
        if ( listen( e ) >= 0 ) {
            Loop::addConnection( this );
            ::log( "Started: " + description() );
        }
    }

    ~Listener()
    {
        if ( state() == Listening )
            Loop::removeConnection( this );
    }

    void read() {}
    void write() {}
    bool canRead() { return true; }
    bool canWrite() { return false; }
    String description() const {
        return svc + " " + Connection::description();
    }

    void react( Event e )
    {
        switch (e) {
        case Read:
            break;
        default:
            log( "Stopped: " + description() );
            setState( Closing );
            break;
        }

        if ( state() == Closing )
            return;

        int s = accept();
        if ( s >= 0 ) {
            Connection *c = new T(s);
            c->setState( Connected );
            log( "Accepted new " + svc + " connection from " +
                 c->peer().string() );
        }
    }

    static void create( const String &svc, const String &address, uint port )
    {
        Listener<T> * l = 0;

        Configuration::Text a( svc.lower() + "-address", address );
        Configuration::Scalar p( svc.lower() + "-port", port );
        if ( !a.valid() && !p.valid() ) {
            ::log( svc +
                   ": Cannot be started due to configuration problems with " +
                   ( a.valid() ? p.name() : a.name() ),
                   Log::Disaster );
        }
        else if ( ((String)a).isEmpty() ) {
            Listener<T> * six = new Listener<T>( Endpoint( "::", p ), svc );
            if ( six->state() == Listening )
                l = six;
            else
                delete six;

            Listener<T> * four
                = new Listener<T>( Endpoint( "0.0.0.0", p ), svc );
            if ( four->state() == Listening )
                l = four;
            else
                delete four;

            if ( !l )
                ::log( "Cannot listen for " + svc + " on port " + fn( p ) +
                       " (tried IPv4 and IPv6)",
                       Log::Disaster );
        }
        else {
            Endpoint e( a, p );
            l = new Listener<T>( e, svc );
            if ( !e.valid() )
                ::log( "Cannot parse desired endpoint for " + svc + ", " +
                       a + " port " + fn( p ),
                       Log::Disaster );
            else if ( l->state() != Listening )
                ::log( "Cannot listen for " + svc + " on " + e.address(),
                       Log::Disaster );
            else
                ::log( "Started: " + l->description() );
        }
    }

private:
    String svc;
};

#endif
