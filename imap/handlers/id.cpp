// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "id.h"

#include "log.h"


/*! \class Id id.h
    Implements the RFC 2971 ID extension

    This extension lets IMAP clients and servers tell each other which
    version of which program they are, which can be helpful for
    debugging.
*/


/*! This reimplementation logs the client details, which strictly
    speaking is part of execution.
*/

void Id::parse()
{
    space();
    if ( nextChar() == '(' ) {
        step();
        while ( nextChar() != ')' ) {
            String name = string();
            space();
            String value = nstring();
            if ( nextChar() == ' ' )
                space();
            if ( ok() && !name.isEmpty() && !value.isEmpty() )
                log( "Client ID: " + name.simplified() + ": " +
                     value.simplified() );
        }
        require( ")" );
    }
    else {
        nil();
    }
    end();
}


void Id::execute()
{
    String v( Configuration::compiledIn( Configuration::Version ) );
    respond( "ID ("
             "\"name\" \"Archiveopteryx\" "
             "\"version\" \"" + v + "\" "
             "\"compile-time\" \"" __DATE__ " " __TIME__ "\" "
             "\"homepage-url\" \"http://www.archiveopteryx.org\" "
             "\"support-url\" \"http://www.oryx.com\" "
             "\"support-email\" \"info@oryx.com\" "
             "\"vendor\" \"Oryx Mail Systems GmbH\")" );
    finish();
}
