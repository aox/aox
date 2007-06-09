// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTENER_H
#define LISTENER_H

#include "connection.h"
#include "configuration.h"
#include "eventloop.h"
#include "resolver.h"
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

        uint c = 0;
        String a = Configuration::text( address );
        uint p = Configuration::scalar( port );
        StringList addresses;
        bool any6 = false;

        if ( a.isEmpty() ) {
            addresses.append( "::" );
            addresses.append( "0.0.0.0" );
        }
        else {
            // XXX: Hack to make it compile
            StringList::Iterator it( Resolver::resolve( a ) );
            while ( it ) {
                addresses.append( *it );
                ++it;
            }
        }

        StringList::Iterator it( addresses );
        while ( it ) {
            Endpoint e( *it, p );
            if ( e.valid() ) {
                bool u = true;
                switch ( e.protocol() ) {
                case Endpoint::IPv4:
                    u = Configuration::toggle( Configuration::UseIPv4 );
                    break;
                case Endpoint::IPv6:
                    u = Configuration::toggle( Configuration::UseIPv6 );
                    break;
                case Endpoint::Unix:
                    break;
                }
                if ( u ) {
                    Listener<T> * l = new Listener<T>( e, svc, i );
                    if ( l->state() != Listening ) {
                        delete l;
                        l = 0;
                        if ( any6 && *it == "0.0.0.0" ) {
                            // if we listen on all addresses using
                            // ipv6 syntax, some platforms also listen
                            // to all ipv4 addresses, and an explicit
                            // ipv4 listen will fail. ignore that
                            // silently.
                            ::log( "Assuming that listening on all IPv6 "
                                   "addresses also listens on IPv4." );
                        }
                        else {
                            ::log( "Cannot listen for " + svc + " on " + *it,
                                   Log::Disaster );
                        }
                    }
                    else {
                        ::log( "Started: " + l->description() );
                        c++;
                        if ( *it == "::" )
                            any6 = true;
                    }
                }
                else {
                    String r;
                    r.append( "Ignoring address " );
                    r.append( e.address() );
                    if ( !a.isEmpty() ) {
                        r.append( " (from " );
                        r.append( a );
                        r.append( ")" );
                    }
                    r.append( " for " );
                    r.append( svc );
                    r.append( " due to configuration settings "
                              "(use-ipv4 and use-ipv6)" );
                    ::log( r );
                }
            }
            else {
                ::log( "Endpoint invalid: " + *it, Log::Error );
            }
            ++it;
        }

        if ( addresses.isEmpty() )
            ::log( "Cannot resolve '" + a + "' for " + svc, Log::Disaster );
        else if ( !c )
            ::log( "Cannot listen for " + svc + " on port " + fn( p ),
                   Log::Disaster );
        else
            ::log( "Listening for " + svc + " on port " + fn( p ) +
                   " of '" + a + "' (" + fn( c ) + " addresses)" );
    }

private:
    String svc;
    bool i;
};

#endif
