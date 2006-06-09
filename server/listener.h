// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTENER_H
#define LISTENER_H

#include "connection.h"
#include "configuration.h"
#include "eventloop.h"
#include "string.h"
#include "log.h"


template< class T >
class Listener
    : public Connection
{
public:
    Listener( const Endpoint &e, const String & s, bool internal )
        : Connection(), svc( s ), i( internal )
    {
        setType( Connection::Listener );
        if ( listen( e ) >= 0 ) {
            EventLoop::global()->addConnection( this );
        }
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
                 c->peer().string(), i ? Log::Debug : Log::Info );
        }
    }

    static void create( const String &svc, bool use,
                        Configuration::Text address,
                        Configuration::Scalar port, bool i )
    {
        if ( !use )
            return;

        Listener< T > *l = 0;
        String a = Configuration::text( address );
        uint p = Configuration::scalar( port );

        if ( a.isEmpty() ) {
            bool use6 = Configuration::toggle( Configuration::UseIPv6 );
            bool use4 = Configuration::toggle( Configuration::UseIPv4 );

            if ( use6 ) {
                Listener< T > *six =
                    new Listener< T >( Endpoint( "::", p ), svc, i );
                if ( six->state() == Listening )
                    l = six;
                else
                    delete six;
            }

            if ( use4 ) {
                Listener< T > *four =
                    new Listener< T >( Endpoint( "0.0.0.0", p ), svc, i );
                if ( four->state() == Listening )
                    l = four;
                else
                    delete four;
            }

            if ( !l )
                ::log( "Cannot listen for " + svc + " on port " + fn( p ) +
                       " (tried IPv4 and IPv6)",
                       Log::Disaster );
            else
                ::log( "Started: " + l->description() );
        }
        else {
            Endpoint e( address, port );
            l = new Listener< T >( e, svc, i );
            if ( !e.valid() || l->state() != Listening ) {
                delete l;
                ::log( "Cannot listen for " + svc + " on " + e.address(),
                       Log::Disaster );
            }
            else {
                ::log( "Started: " + l->description() );
            }
        }
    }

private:
    String svc;
    bool i;
};

#endif
