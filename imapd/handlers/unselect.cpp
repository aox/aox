/*! \class Unselect unselect.h
    Implements the RFC 3691 UNSELECT extension

    The extension is extremely simple: It adds the single command
    "unselect" to change from Selected to Authenticated state.
    Unlike Close, Unselect does not expunge.
*/

#include "unselect.h"

#include "imap.h"


void Unselect::execute()
{
    imap()->endSession();
    finish();
}
