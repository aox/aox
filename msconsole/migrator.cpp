// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "migrator.h"


/*!  Constructs an empty

*/

Migrator::Migrator( QWidget * parent )
    : QWidget( parent )
{
    
}


/*! Returns true if a Migrator operation is currently running, and
    false otherwise. An operation is running even if there's nothing
    it can do at the moment because of syntax errors or permission
    problems.
*/

bool Migrator::running() const
{
    return false;
}
