// Copyright Arnt Gulbrandsen <arnt@gulbrandsen.priv.no>.

#include "move.h"


/*! \class Move move.h
    A thin wrapper around Copy to provide MOVE and UID MOVE command.
*/


/*! Persuades Copy to do what Move needs. \a uid is true for UID MOVE,
    false for MOVE.
*/

Move::Move( bool uid )
    : Copy( uid )
{
    setMove();
}
