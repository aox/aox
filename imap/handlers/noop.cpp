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

    Performs a checkpoint of the selected mailbox (RFC 3501 section
    6.4.1), which is a noop for in all the implementations I know.
*/

void Check::execute()
{
    finish();
}
