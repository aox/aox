#ifndef LISTENER_H
#define LISTENER_H

#include "connection.h"
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
        if ( listen( e ) >= 0 )
            Loop::addConnection( this );
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
            Loop::addConnection( c );
        }
    }

    static void create( const String &svc, const String &address, uint port )
    {
        Listener<T> * l;

        if ( address.isEmpty() ) {
            l = new Listener<T>( Endpoint( "::", port ), svc );
            if ( l->state() == Listening )
                log( "Started: " + l->description() );
            else
                delete l;

            l = new Listener<T>( Endpoint( "0.0.0.0", port ), svc );
            if ( l->state() == Listening )
                log( "Started: " + l->description() );
            else
                delete l;
        }
        else {
            l = new Listener<T>( Endpoint( address, port ), svc );
            if ( l->state() == Listening )
                log( "Started: " + l->description() );
            else
                delete l;
        }
    }

private:
    String svc;
};

#endif
