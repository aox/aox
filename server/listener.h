// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LISTENER_H
#define LISTENER_H

#include "connection.h"
#include "configuration.h"
#include "eventloop.h"
#include "resolver.h"
#include "estring.h"
#include "log.h"


template< class T >
class Listener
    : public Connection
{
public:
    Listener( const Endpoint &e, const EString & s, bool silent = false )
        : Connection(), svc( s )
    {
        setType( Connection::Listener );
        if ( listen( e, silent ) >= 0 ) {
            EventLoop::global()->addConnection( this );
        }
    }

    void read() {}
    void write() {}
    bool canRead() { return true; }
    bool canWrite() { return false; }
    EString description() const {
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
            Connection * c = new T(s);
            c->setState( Connected );
        }
    }

    static void create( const EString &svc, bool use,
                        Configuration::Text address,
                        Configuration::Scalar port )
    {
        if ( !use )
            return;

        bool use4 = Configuration::toggle( Configuration::UseIPv4 );
        bool use6 = Configuration::toggle( Configuration::UseIPv6 );

        uint c = 0;
        EString a = Configuration::text( address );
        uint p = Configuration::scalar( port );
        EStringList addresses;
        bool any6 = false;

        if ( a.isEmpty() ) {
            if ( use6 )
                addresses.append( "::" );
            if ( addresses.isEmpty() || !any6ListensTo4() )
                addresses.append( "0.0.0.0" );
        }
        else {
            // XXX: Hack to make it compile
            EStringList::Iterator it( Resolver::resolve( a ) );
            while ( it ) {
                addresses.append( *it );
                ++it;
            }
        }

        EStringList::Iterator it( addresses );
        while ( it ) {
            Endpoint e( *it, p );
            if ( e.valid() ) {
                bool u = true;
                switch ( e.protocol() ) {
                case Endpoint::IPv4:
                    u = use4;
                    break;
                case Endpoint::IPv6:
                    u = use6;
                    break;
                case Endpoint::Unix:
                    break;
                }
                if ( u ) {
                    bool silent = false;
                    if ( any6 && *it == "0.0.0.0" )
                        silent = true;
                    Listener<T> * l = new Listener<T>( e, svc, silent );
                    if ( l->state() != Listening ) {
                        delete l;
                        l = 0;
                        if ( silent ) {
                            // if we listen on all addresses using
                            // ipv6 syntax, some platforms also listen
                            // to all ipv4 addresses, and an explicit
                            // ipv4 listen will fail. ignore that
                            // silently.
                            ::log( "Assuming that listening on all IPv6 "
                                   "addresses also listens on IPv4." );
                            setAny6ListensTo4( true );
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
                    EString r;
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
        else if ( c > 1 )
            ::log( "Listening for " + svc + " on port " + fn( p ) +
                   " of '" + a + "' (" + fn( c ) + " addresses)" );
    }

private:
    EString svc;
};

#endif
