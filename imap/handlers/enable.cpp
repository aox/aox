// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "enable.h"

#include "capability.h"


/*! \class Enable enable.h

    The Enable class implements the IMAP ENABLE command, defined by
    draft-gulbrandsen-imap-enable. Really simple command.
*/



Enable::Enable()
    : Command(), condstore( false ), annotate( false )
{
}


void Enable::parse()
{
    if ( !nextChar() == ' ' )
        error( Bad, "No capabilities enabled" );
    while ( ok() && nextChar() == ' ' ) {
        space();
        String capability = atom().upper();
        if ( capability == "CONDSTORE" ) {
            condstore = true;
        }
        else if ( capability == "ANNOTATE" ) {
            annotate = true;
        }
        else {
            String all = Capability::capabilities( imap(), true ).upper();
            StringList::Iterator s( StringList::split( ' ', all ) );
            while ( s && capability != *s )
                ++s;
            if ( s )
                error( Bad, "Capability " + *s + " is not subject to Enable" );
        }
    }
    end();
}


void Enable::execute()
{
    if ( condstore )
        imap()->setClientSupports( IMAP::Condstore );
    if ( annotate )
        imap()->setClientSupports( IMAP::Annotate );
    finish();
}
