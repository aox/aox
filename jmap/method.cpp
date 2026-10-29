// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "method.h"

#include "json.h"
#include "user.h"


class JmapMethodData
    : public Garbage
{
public:
    JmapMethodData()
        : owner( 0 ), user( 0 ), arguments( 0 ), response( 0 ), done( false )
    {}

    EventHandler * owner;
    User * user;
    Json * arguments;
    Json * response;
    EString name;
    bool done;
};


/*! \class JmapMethod method.h

    The JmapMethod class models one JMAP method call: it holds the
    arguments, asks the database whatever it needs to ask, and ends
    with either a response or an error.
*/


/*! Constructs a method call for \a user with \a arguments, which will
    notify \a owner when it has an answer.
*/

JmapMethod::JmapMethod( EventHandler * owner, User * user, Json * arguments )
    : d( new JmapMethodData )
{
    d->owner = owner;
    d->user = user;
    d->arguments = arguments;
}


/*! Returns true once this method has a response() to send. */

bool JmapMethod::done() const
{
    return d->done;
}


/*! Returns the response arguments, or a null pointer if the method is
    not done() yet.
*/

Json * JmapMethod::response() const
{
    return d->response;
}


/*! Returns the name the response goes out under: the method's own
    name, or "error".
*/

EString JmapMethod::responseName() const
{
    return d->name;
}


/*! Returns the arguments this method was called with. */

Json * JmapMethod::arguments() const
{
    return d->arguments;
}


/*! Returns the user whose mail this method reads. */

User * JmapMethod::user() const
{
    return d->user;
}


/*! Records \a response as the answer, to be sent as \a name, and
    notifies the owner.
*/

void JmapMethod::respond( const EString & name, Json * response )
{
    d->name = name;
    d->response = response;
    d->done = true;
    d->owner->execute();
}


/*! Records the method-level error \a type as the answer. RFC8620
    3.6.2 lists the types.
*/

void JmapMethod::fail( const EString & type )
{
    Json * e = Json::object();
    e->insert( "type", Json::string( type ) );
    respond( "error", e );
}


/*! Checks the accountId argument, if there is one, and returns true
    if this method may proceed. Answers accountNotFound and returns
    false if the client asked about an account that is not this user's.
*/

bool JmapMethod::checkAccount()
{
    Json * a = d->arguments->member( "accountId" );
    if ( !a )
        return true;
    if ( a->valid( Json::String ) && a->ascii() == fn( d->user->id() ) )
        return true;
    fail( "accountNotFound" );
    return false;
}
