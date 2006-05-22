// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "resolver.h"

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>


class ResolverData
    : public Garbage
{
public:
    StringList errors;
    Dict<StringList> names;
};


/*! \class Resolver resolver.h

    The Resolver class performs DNS lookups and caches the results
    until the process exits. It does not consider the TTLs on the DNS
    results.

    The only public functions are resolve(), which does a cache lookup
    and failing that, a DNS lookup, and errors(), which returns a list
    of all errors seen so far. A server can ensure that it calls
    resolve() at startup time for all required names, and if errors()
    remains empty, all is well and remains well until the end of the
    process.

    We need a class called Revolver.
*/


/*! Constructs an empty Resolver. This constructor is private; in
    general, Resolver is used via the static function resolve().
*/

Resolver::Resolver()
    : Garbage(), d( new ResolverData )
{

}


/*! Resolves \a name and returns a list of results, or returns a
    cached list of results if resolve() has been called for \a name
    already.

    \a name is assumed to be case-insensitive.

    Any errors are added to an internal list and can be retrieved with
    errors().
*/

StringList Resolver::resolve( const String & )
{
    Resolver * r = resolver();
    String name = s.lower();
    if ( r->d->names.contains( name ) )
        return *r->d->find( name );

    StringList results;
    if ( name == "localhost" ) {
        results.append( "::1" );
        results.append( "127.0.0.1" );
    }
    else if ( name.contains( ':' ) ) {
        // it's an ipv6 address
    }
    else if ( name.contains( '.' ) && name.mid( name.length()-1 ) <= '9' ) {
        // it's an ipv4 address
    }
    else if ( name.startsWith( '/' ) ) {
        // it's a unix pipe
    }
    else {
        // it's a domain name. we use res_search since getnameinfo()
        // had such bad karma when we tried it.
        if ( Configuration::toggle( Configuration::UseIPv6 ) ) {
        }
        if ( Configuration::toggle( Configuration::UseIPv4 ) ) {
            int len = res_search( name.cstr(), C_IN, T_INADDR, answer, 4096 );
            if ( len > 0 )
                results.append( parse( answer ) );
        }
    }
    r->d->names.insert( name, results );
    return results;
}


/*! Returns a list of one-line error messages concerning all
    resolution errors since startup.
*/

StringList Resolver::errors()
{
    return resolver()->d->errors;
}


/*! This private helper ensures that there is a resolver, and returns
    a pointer to it.
*/

Resolver * Resolver::resolver()
{
    if ( ::resolver )
        return ::resolver;

    ::resolver = new Resolver;
    Allocator::addEternal( ::resolver, "name resolver" );
    return ::resolver;
}


/* Reads and returns a single string from the stored DNS reply at
   offset \a i, modifying \a i. If errors occur, an error is
   logged. If the parser runs off the end of the reply, readString()
   returns an empty string, but logs no error.
*/


String Resolver::readString( uint & i )
{
    bool ok = true;
    bool bad = false;
    String r;
    b = d->reply[i];
    if ( i >= d->reply.length() ) {
        ok = false;
    }
    if ( b == 0 ) {
        // all is in perfect order
    }
    else if ( b < 64 ) {
        i++;
        r.append( d->reply+i, b );
        b += i;
        // and just in case that wasn't all, do a spot of tail recursion
        r.append( readString() );
    }
    else if ( b >= 192 ) {
        uint qi = ( ( d->reply[i] & 0x3f ) << 8 ) + d->reply[i+1];
        if ( qi < i )
            r.append( readString( qi ) );
        else
            bad = true;
        i += 2;
    }
    else {
        bad = true;
    }
    if ( bad )
        d->errors.append( "DNS error while resolving " + d->host );
    else if ( ok )
        return r;
    return "";
}



/*! This private function issues a DNS query of \a type for \a name
    and caches all results. \a type is passed through to ::res_query()
    unchanged.
*/

void Resolver::query( String name, uint t )
{
    d->reply.reserve( 4096 );
    int len = res_search( name.cstr(), C_IN, t, d->reply, 4096 );
    if ( len <= 0 ) {
        d->errors.append( "Error while looking up " + name );
        return;
    }
        
    d->reply.truncate( len );
    
    uint p = 12;

    if ( len < 12 )
        return;

    uint qdcount = (  answer[4] << 8 ) +  answer[5];
    uint ancount = (  answer[6] << 8 ) +  answer[7];

    // skip the query section
    while ( p < d->reply.length() && qdcount && !d->bad ) {
        (void)readString( p );
        p += 4;
        qdcount--;
    }

    // parse each A and AAAA in the answer section
    while ( p < d->reply.length() && ancount && !d->bad  ) {
        String n = readString( p );
        String a;
        uint type = ( d->reply[p] << 8 ) + d->reply[p+1];
        uint rdlength = ( d->reply[p+8] << 8 ) + d->reply[p+9];
        p += 10;
        if ( type == T_INADDR ) {
            if ( rdlength == 4 ) {
                uint i = 0;
                while ( i < rdlength ) {
                    if ( !a.isEmpty() )
                        a.append( '.' );
                    a.append( fn( d->reply[p+i] ) );
                    i++;
                }
            }
        }
        else if ( type == T_INADDR6 ) {
            if ( rdlength == 16 ) {
                uint i = 0;
                while ( i < rdlength ) {
                    if ( !a.isEmpty() )
                        a.append( ':' );
                    a.append( fn( ( d->reply[p+i] << 8 ) + d->reply[p+i+1], 16 ) );
                    i += 2;
                }
            }
        }
        p += rdlength;
        if ( p <= d->reply.length() && !d->bad && !a.isEmpty() ) {
            
        }
        ancount--;
    }

    // we don't care about the NS and AD sections, so we're done
}
