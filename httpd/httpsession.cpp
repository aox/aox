// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "httpsession.h"

#include "allocator.h"
#include "entropy.h"
#include "string.h"
#include "user.h"
#include "dict.h"

// time
#include <time.h>


static Dict< HttpSession > *sessions;


class HttpSessionData {
public:
    HttpSessionData()
        : user( 0 )
    {}

    String key;
    User *user;
    int timeout;
};


/*! \class HttpSession httpsession.h
    This class represents a single HTTP user session.
*/

/*! Creates a new HttpSession and refresh()es it. */

HttpSession::HttpSession()
    : d( new HttpSessionData )
{
    if ( !sessions ) {
        sessions = new Dict< HttpSession >;
        Allocator::addEternal( sessions, "Session cache" );
    }
    d->key = Entropy::asString( 42 ).encode( String::Base64 );
    sessions->insert( d->key, this );
    refresh();
}


/*! Returns the key that identifies this session.
    The key is about 60 bytes long, and is suitable for use as a cookie
    (if you don't look too carefully).
*/

String HttpSession::key() const
{
    return d->key;
}


/*! Returns a pointer to the user associated with this session, or 0 if
    the user has not yet logged in.
*/

User *HttpSession::user() const
{
    return d->user;
}


/*! Sets the user associated with this session to \a u. */

void HttpSession::setUser( User *u )
{
    d->user = u;
}


/*! Resets the expiry counter for this session, such that access is
    permitted for another {configured session timeout interval} seconds.
*/

void HttpSession::refresh()
{
    d->timeout = ::time( 0 ) + 7200;
}


/*! Sets the expiry counter for this session to a value in the past,
    such that access is denied immediately.
*/

void HttpSession::expireNow()
{
    d->timeout = 0;
}


/*! Returns true if this session had not been refresh()ed in the last
    {configured session timeout interval} seconds.
*/

bool HttpSession::expired() const
{
    if ( ::time( 0 ) > d->timeout )
        return true;
    return false;
}


/*! Returns a pointer to the HttpSession identified by \a key, or 0 if
    there is no such session. The returned session may have expired().
*/

HttpSession *HttpSession::find( const String &key )
{
    if ( sessions )
        return sessions->find( key );
    return 0;
}
