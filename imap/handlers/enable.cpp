// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "enable.h"

#include "capability.h"


/*! \class Enable enable.h

    The Enable class implements the IMAP ENABLE command as defined by
    RFC 5161. Really simple command.
*/



Enable::Enable()
    : Command(),
      condstore( false ), annotate( false ), utf8( false ), qresync( false )
{
}


void Enable::parse()
{
    if ( nextChar() != ' ' )
        error( Bad, "No capabilities enabled" );
    while ( ok() && nextChar() == ' ' ) {
        space();
        EString capability = atom().upper();
        if ( capability == "CONDSTORE" ) {
            condstore = true;
        }
        else if ( capability == "ANNOTATE-EXPERIMENT-1" ) {
            annotate = true;
        }
        else if ( capability == "UTF8=ACCEPT" ) {
            utf8 = true;
        }
        else if ( capability == "QRESYNC" ) {
            qresync = true;
        }
        else {
            EString all = Capability::capabilities( imap(), true ).upper();
            EStringList::Iterator s( EStringList::split( ' ', all ) );
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
    EString r = "ENABLED";
    if ( condstore ) {
        imap()->setClientSupports( IMAP::Condstore );
        r.append( " CONDSTORE" );
    }
    if ( annotate ) {
        imap()->setClientSupports( IMAP::Annotate );
        r.append( " ANNOTATE-EXPERIMENT-1" );
    }
    if ( utf8 ) {
        imap()->setClientSupports( IMAP::Unicode );
        r.append( " UTF8=ACCEPT" );
    }
    if ( qresync ) {
        imap()->setClientSupports( IMAP::QResync );
        r.append( " QRESYNC" );
    }
    respond( r );
    finish();
}
