// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievescript.h"


class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage() {}
};


/*! \class SieveScript sievescript.h

    The SieveScript class knows how to parse a Sieve script and
    remember the rules.
 */


/*! Constructs an empty Sieve script. This may be filled in by
    construcing sieve rules with this script as parent.
*/

SieveScript::SieveScript()
    : Garbage()
{

}
