// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

/*! \class Close close.h
    Performs a silent EXPUNGE+UNSELECT (RFC 3501, §6.4.2)

    Four lines of code and seemingly correct.

    Since Close is a variant of Expunge, this class inherits Expunge
    and switches to authenticated state after a silent expunge.

    The Unselect command is similar to this, but does not
    expunge. Perhaps Close should inherit Unselect rather than
    Expunge. It doesn't really matter - at best we might save one line
    of code.
*/

#include "close.h"

#include "imap.h"


void Close::execute()
{
    expunge( false );
    imap()->endSession();
    finish();
}
