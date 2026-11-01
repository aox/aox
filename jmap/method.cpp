// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "method.h"

#include "json.h"
#include "user.h"
#include "integerset.h"


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


/*! Decides how much of a set of changes to report at once, and
    returns the modseq to report as the new state.

    \a candidates are the objects that changed, \a first says at which
    modseq each of them first changed, and \a maxChanges is what the
    client will accept. The objects to report are added to \a included,
    and \a more is set if any were left out.

    Changes that share a modseq are never split, because the client
    must be able to continue from the state this returns and would
    otherwise never see the rest of the group. A single group larger
    than \a maxChanges is therefore reported whole: the alternative is
    to report nothing and never make progress.
*/

int64 JmapMethod::splitChanges( const IntegerSet & candidates,
                                Map<int64> & first, uint maxChanges,
                                IntegerSet & included, bool & more )
{
    int64 boundary = 0;
    uint taken = 0;
    bool looking = true;
    while ( looking ) {
        int64 next = 0;
        uint group = 0;
        uint n = 1;
        while ( n <= candidates.count() ) {
            int64 m = *first.find( candidates.value( n ) );
            if ( m > boundary && ( !next || m < next ) ) {
                next = m;
                group = 0;
            }
            if ( next && m == next )
                group++;
            n++;
        }
        if ( !next )
            looking = false;
        else if ( taken && taken + group > maxChanges )
            looking = false;
        else {
            boundary = next;
            taken += group;
        }
    }

    uint n = 1;
    while ( n <= candidates.count() ) {
        uint id = candidates.value( n );
        if ( *first.find( id ) <= boundary )
            included.add( id );
        else
            more = true;
        n++;
    }
    return boundary;
}
