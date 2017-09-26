// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "create.h"

#include "imap.h"
#include "user.h"
#include "mailbox.h"
#include "transaction.h"


class CreateData
    : public Garbage
{
public:
    CreateData(): m( 0 ), parent( 0 ) {}
    UString name;
    Mailbox * m;
    Mailbox * parent;
    EString attr;
};


/*! \class Create create.h
    Creates a new mailbox (RFC 3501 section 6.3.3)

    The mailboxes table contains an entry for each deliverable mailbox
    that has ever existed in the database. This class either inserts a
    new entry, or resurrects a previously deleted one.
*/

Create::Create()
    : d( new CreateData )
{
}


void Create::parse()
{
    space();
    d->name = mailboxName();
    if ( present( " (" ) ) {
        parseCreateParam();
        while ( present( " " ) )
            parseCreateParam();
        require( ")" );
    }
    end();
    if ( d->name.titlecased() == imap()->user()->inbox()->name().titlecased() )
        error( No, "INBOX always exists" );
    log( "Create " + d->name.ascii() );
}


void Create::parseCreateParam()
{
    if ( !present( "use (" ) )
        error( Bad, "Unknown create parameter" );
    parseUseAttr();
    while ( present( " " ) )
        parseUseAttr();
    require( ")" );
}

void Create::parseUseAttr()
{
    require("\\");
    EString attr = "\\" + atom();
    if ( attr == "\\all" || attr == "\\archive" || attr == "\\drafts" ||
         attr == "\\flagged" || attr == "\\junk" || attr == "\\sent" ||
         attr == "\\trash" ) {
        if ( d->attr.isEmpty() || d->attr == attr ) {
            // fine
            d->attr = attr;
        } else {
            error( No, "Archiveopteryx supports only one flag per mailbox" );
        }
    } else {
        error( No, "Unknown attribute" );
    }
}


void Create::execute()
{
    if ( state() != Executing )
        return;

    if ( !d->parent ) {
        d->parent = Mailbox::closestParent( d->name );
        if ( !d->parent ) {
            error( No, "Syntax error in mailbox name: " + d->name.ascii() );
            setRespTextCode( "CANNOT" );
            return;
        }

        requireRight( d->parent, Permissions::CreateMailboxes );
    }

    if ( !permitted() )
        return;

    if ( !transaction() ) {
        d->m = Mailbox::obtain( d->name, true );
        setTransaction( new Transaction( this ) );
        if ( !d->m ) {
            error( No, d->name.ascii() + " is not a valid mailbox name" );
            return;
        }
        d->m->setFlag( d->attr );
        if ( d->m->create( transaction(), imap()->user() ) == 0 ) {
            error( No, d->name.ascii() + " already exists" );
            setRespTextCode( "ALREADYEXISTS" );
            return;
        }
        Mailbox::refreshMailboxes( transaction() );
        transaction()->commit();
    }

    if ( !transaction()->done() )
        return;

    if ( transaction()->failed() ) {
        error( No, "Database error: " + transaction()->error() );
        return;
    }

    finish();
}
