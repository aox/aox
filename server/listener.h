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
        : Connection()
    {
        svc = s;
        if ( listen(e) >= 0 )
            Loop::addConnection( this );
    }

    void read() {}
    void write() {}
    bool canRead() { return true; }
    bool canWrite() { return false; }

    void react( Event e )
    {
        switch (e) {
        case Read:
            break;
        default:
            // XXX: This should be log(), but it segfaults.
            // Will investigate later. -- AMS 20040330
            Log::global()->log( svc + " listener stopped" );
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
        bool listening = false;
        Listener<T> * l;

        if ( address.isEmpty() ) {
            l = new Listener<T>( Endpoint( "::", port ), svc );
            if ( l->state() != Listening )
                delete l;
            else
                listening = true;

            l = new Listener<T>( Endpoint( "0.0.0.0", port ), svc );
            if ( l->state() != Listening )
                delete l;
            else
                listening = true;
        }
        else {
            l = new Listener<T>( Endpoint( address, port ), svc );
            if ( l->state() != Listening )
                delete l;
            else
                listening = true;
        }

        if ( listening )
            log( svc + " listener started" );
    }

private:
    String svc;
};

#endif
