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
                 c->peer().string() );
        }
    }

    static void create( const String &svc )
    {
        Listener< T > *l = 0;

        bool use;
        Configuration::Text address;
        Configuration::Scalar port;

        String s = svc.lower();
        if ( s == "log" ) {
            use = 1;
            address = Configuration::LogAddress;
            port = Configuration::LogPort;
        }
        else if ( s == "ocd" ) {
            use = 1;
            address = Configuration::OcdAddress;
            port = Configuration::OcdPort;
        }
        else if ( s == "ocadmin" ) {
            use = 1;
            address = Configuration::OcAdminAddress;
            port = Configuration::OcAdminPort;
        }
        else if ( s == "imap" ) {
            use = Configuration::toggle( Configuration::UseImap );
            address = Configuration::ImapAddress;
            port = Configuration::ImapPort;
        }
        else if ( s == "imaps" ) {
            use = Configuration::toggle( Configuration::UseImaps );
            address = Configuration::ImapsAddress;
            port = Configuration::ImapsPort;
        }
        else if ( s == "smtp" ) {
            use = Configuration::toggle( Configuration::UseSmtp );
            address = Configuration::SmtpAddress;
            port = Configuration::SmtpPort;
        }
        else if ( s == "lmtp" ) {
            use = Configuration::toggle( Configuration::UseLmtp );
            address = Configuration::LmtpAddress;
            port = Configuration::LmtpPort;
        }
        else if ( s == "http" ) {
            use = Configuration::toggle( Configuration::UseHttp );
            address = Configuration::HttpAddress;
            port = Configuration::HttpPort;
        }
        else if ( s == "pop3" ) {
            use = Configuration::toggle( Configuration::UsePop );
            address = Configuration::PopAddress;
            port = Configuration::PopPort;
        }
        else if ( s == "tlsproxy" ) {
            use = Configuration::toggle( Configuration::UseTls );
            address = Configuration::TlsProxyAddress;
            port = Configuration::TlsProxyPort;
        }

        String a = Configuration::text( address );
        uint p = Configuration::scalar( port );

        if ( !use )
            return;

        if ( a.isEmpty() ) {
            bool use6 = Configuration::toggle( Configuration::UseIPv6 );
            bool use4 = Configuration::toggle( Configuration::UseIPv4 );

            if ( use6 ) {
                Listener< T > *six =
                    new Listener< T >( Endpoint( "::", p ), svc );
                if ( six->state() == Listening )
                    l = six;
                else
                    delete six;
            }

            if ( use4 ) {
                Listener< T > *four =
                    new Listener< T >( Endpoint( "0.0.0.0", p ), svc );
                if ( four->state() == Listening )
                    l = four;
                else
                    delete four;
            }

            if ( !l )
                ::log( "Cannot listen for " + svc + " on port " + fn( p ) +
                       " (tried IPv4 and IPv6)",
                       Log::Disaster );
        }
        else {
            Endpoint e( address, port );
            l = new Listener< T >( e, svc );
            if ( !e.valid() || l->state() != Listening )
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
