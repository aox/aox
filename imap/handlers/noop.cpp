// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "noop.h"

#include "mailbox.h"
#include "imapsession.h"


/*! \class Noop noop.h
    NOOP does nothing (RFC 3501 section 6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.
*/

void Noop::execute()
{
    finish();
}



/*! \class Check noop.h
    Performs a checkpoint of the selected mailbox (RFC 3501 section 6.4.1)

    In our implementation, all this does it write "\seen" flags from a
    view to its backing mailbox.
*/

void Check::execute()
{
    Mailbox * m = 0;
    if ( imap()->session() )
        m = imap()->session()->mailbox();
    if ( m )
        m->writeBackMessageState();

    finish();
}
