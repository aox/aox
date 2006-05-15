// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievescript.h"


class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage() {}
};


/*!  Constructs an empty Sieve script. This may be filled in by
     construcing sieve rules with this script as parent.
*/

SieveScript::SieveScript()
    : Garbage()
{
    
}
