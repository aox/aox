/*! \class Id id.h
    \brief The Id class implements the RFC2971 ID extension.

    This extension lets IMAP clients and servers tell each other which
    version of which program they are, which can be helpful for
    debugging.
*/

#include "id.h"

#include "log.h"


void Id::parse()
{
    if ( nextChar() == '(' ) {
        step();
        while ( nextChar() != ')' ) {
            String name = string();
            space();
            String value = nstring();
            if ( nextChar() == ' ' )
                space();
            if ( ok() && !name.isEmpty() && !value.isEmpty() )
                logger()->log( "Client ID: " + 
                               name.simplified() + ": " + 
                               value.simplified() );
        }
    }
    else {
        nil();
    }
}


void Id::execute()
{
    respond( "ID ("
             "\"name\" \"Oryx IMAP Gateway\" "
             "\"version\" \"snapshot\" "
             "\"compile-time\" \"" __DATE__ " " __TIME__ "\" "
             "\"support-url\" \"http://www.oryx.com\" "
             "\"vendor\" \"Oryx Mail Systems GmbH\")" );
    setState( Finished );
}
