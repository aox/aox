// Copyright Arnt Gulbrandsen <arnt@gulbrandsen.priv.no>.

#include "move.h"


/*! \class Move move.h
    A thin wrapper around Move to provide an UID MOVE command.
*/


/*! Persuades Copy to do what Move needs. \a uid is true for UID MOVE,
    false for MOVE.
*/

Move::Move( bool uid )
    : Copy( uid )
{
    setMove();
}
