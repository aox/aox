// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

/*! \class Close close.h
    Performs a silent EXPUNGE+UNSELECT (RFC 3501 section 6.4.2)

    Four lines of code and seemingly correct.

    Since Close is a variant of Expunge, this class inherits Expunge
    and switches to authenticated state after a silent expunge.
*/

#include "close.h"

#include "imap.h"


void Close::execute()
{
    if ( state() != Executing )
        return;
    Expunge::execute();
    if ( imap()->session() )
        imap()->endSession();
}
