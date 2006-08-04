// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"

#include "allocator.h"
#include "global.h"
#include "log.h"


Scope * currentScope = 0;


/*! \class Scope scope.h
    A mechanism to save and restore context between scopes.

    A scope allows parts of the code to change global state (such as the
    current log) during execution, and restore it afterwards. Objects
    of this class should be declared as automatic variables so that the
    destructor is called when execution leaves the lexical scope.

    Note that the root scope must be declared with an explicit log, or
    the first logging statement will fail.
*/


/*! Creates and enters a new scope that shares all the attributes of
    its enclosing scope. If there is no current scope, the new scope
    has no log.

    The new scope is made current.
*/

Scope::Scope()
    : parent( currentScope ), currentLog( 0 )
{
    currentScope = this;
    if ( parent )
        setLog( parent->log() );
}


/*! Creates and enters a new scope that has log \a l.
    The new scope is made current.
*/

Scope::Scope( Log *l )
    : parent( currentScope ), currentLog( 0 )
{
    currentScope = this;
    setLog( l );
}


/*! If this scope is the current scope, then the previous current
    scope is made current again.

    If not, an exception is thrown. The case could be handled - we
    used to have code to handle this in Arena.
*/

Scope::~Scope()
{
    setLog( 0 );
    if ( currentScope == this )
        currentScope = parent;
    else
        die( Memory );
}


/*! Returns a pointer to the current scope, or a null pointer if no
    scope has been created.
*/

Scope *Scope::current()
{
    return currentScope;
}


/*! Returns a pointer to the current scope log, or a null pointer if
    the current Scope has no Log.
*/

Log *Scope::log() const
{
    return currentLog;
}


/*! Sets the scope log to \a l. The previous Log is not affected. In
    particular, the previous Log is not commited. Should it be?
    Probably.
*/

void Scope::setLog( Log *l )
{
    if ( currentLog )
        Allocator::removeEternal( currentLog );
    currentLog = l;
    if ( currentLog )
        Allocator::addEternal( currentLog,
                               "a log object referred to by Scope" );
}


