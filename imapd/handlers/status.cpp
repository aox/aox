// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "status.h"

#include "imap.h"
#include "mailbox.h"
#include "imapsession.h"


/*! \class Status status.h
    Returns the status of the specified mailbox (RFC 3501 section 6.3.10)
*/

Status::Status()
    : messages( false ), uidnext( false ), uidvalidity( false ),
      recent( false ), unseen( false ),
      m( 0 ), session( 0 )
{}


void Status::parse()
{
    space();
    name = astring();
    space();
    require( "(" );

    while ( 1 ) {
        String item = letters( 1, 11 ).lower();

        if ( item == "messages" )
            messages = true;
        else if ( item == "recent" )
            recent = true;
        else if ( item == "uidnext" )
            uidnext = true;
        else if ( item == "uidvalidity" )
            uidvalidity = true;
        else if ( item == "unseen" )
            unseen = true;
        else
            error( Bad, "Unknown STATUS item " + item );

        if ( nextChar() == ' ' )
            space();
        else
            break;
    }

    require( ")" );
    end();
}


void Status::execute()
{
#if 0
    if ( !m ) {
        m = Mailbox::find( imap()->mailboxName( name ) );
        if ( !m ) {
            error( No, "Can't open " + name );
            finish();
            return;
        }

        if ( unseen || recent )
            session = new ImapSession( m, true, this );
    }

    if ( session && !session->loaded() )
        return;

    String status;

    if ( messages )
        status.append( "MESSAGES " + fn( m->count() ) + " " );
    if ( recent )
        status.append( "RECENT " + fn( m->recent() ) + " " );
    if ( uidnext )
        status.append( "UIDNEXT " + fn( m->uidnext() ) + " " );
    if ( uidvalidity )
        status.append( "UIDVALIDITY " + fn( m->uidvalidity() ) + " " );
    if ( unseen )
        status.append( "UNSEEN " + fn( m->unseen() ) + " " );

    status.truncate( status.length()-1 );
    respond( "STATUS " + name + " (" + status + ")" );
#endif

    finish();
}
