// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"

#include "allocator.h"
#include "global.h"
#include "list.h"
#include "log.h"


static List<ScopeData> * scopes = 0;

class ScopeData
    : public Garbage
{
public:
    ScopeData(): log( 0 ), scope( 0 ) {
        if ( !::scopes) {
            ::scopes = new List<ScopeData>;
            Allocator::addEternal( ::scopes,
                                   "(indirect) pointer to current scope" );
        }

        ScopeData * parent = 0;
        if ( ::scopes )
            parent = ::scopes->firstElement();

        ::scopes->prepend( this );

        if ( parent )
            log = parent->log;
    }
    ~ScopeData() {
        scope = 0;
        bool bad = false;
        if ( !::scopes ) {
            bad = true;
        }
        else {
            if ( scopes->firstElement() != this )
                bad = true;
            List<ScopeData>::Iterator i = ::scopes->find( this );
            ::scopes->take( i );
        }
        if ( bad )
            die( Memory );
    }

    Log * log;
    Scope * scope;
};


/*! \class Scope scope.h
    A mechanism to save and restore context between scopes.

    A scope allows parts of the code to change global state (such as the
    current log) during execution, and restore it afterwards. Objects
    of this class should be declared as automatic variables so that the
    destructor is called when execution leaves the lexical scope.

    Note that the root scope must be declared with an explicit log, or
    the first logging statement will fail.

    In order to keep track of scopes, there are some rules: If Scope a
    is created before Scope b, b must be deleted before a. Really
    deleted, Allocator::free() will not free them.
*/


/*! Creates and enters a new scope that shares all the attributes of
    its enclosing scope. If there is no current scope, the new scope
    has no log.

    The new scope is made current.
*/

Scope::Scope()
    : d( new ScopeData )
{
    d->scope = this;
}


/*! Creates and enters a new scope that has log \a l.
    The new scope is made current.
*/

Scope::Scope( Log *l )
    : d( new ScopeData )
{
    d->scope = this;
    setLog( l );
}


/*! If this scope is the current scope, then the previous current
    scope is made current again.

    If not, an exception is thrown. The case could be handled - we
    used to have code to handle this in Arena.
*/

Scope::~Scope()
{
    d->scope = 0;
    delete d;
    d = 0;
}


/*! Returns a pointer to the current scope, or a null pointer if no
    scope has been created.
*/

Scope * Scope::current()
{
    ScopeData * l = 0;
    if ( ::scopes )
        l = ::scopes->firstElement();
    if ( l )
        return l->scope;
    return 0;
}


/*! Returns a pointer to the current scope log, or a null pointer if
    the current Scope has no Log.
*/

Log * Scope::log() const
{
    return d->log;
}


/*! Sets the scope log to \a l. The previous Log is not affected. In
    particular, the previous Log is not commited. Should it be?
    Probably.
*/

void Scope::setLog( Log * l )
{
    d->log = l;
}
