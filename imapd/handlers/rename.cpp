// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "rename.h"

#include "mailbox.h"
#include "permissions.h"


class RenameData
    : public Garbage
{
public:
    RenameData()
        : from( 0 ), to( 0 ),
          fromPermissions( 0 ), toPermissions( 0 ),
          mrcInboxHack( false ) {}
public:
    String fromName;
    String toName;
    Mailbox * from;
    Mailbox * to;
    Permissions * fromPermissions;
    Permissions * toPermissions;
    bool mrcInboxHack;
};


/*! \class Rename rename.h
    Renames a mailbox (RFC 3501 section 6.3.5)
*/


Rename::Rename()
    : d( new RenameData )
{
}


void Rename::parse()
{
    space();
    d->fromName = astring();
    space();
    d->toName = astring();
    end();
}


void Rename::execute()
{
    if ( !d->from ) {
        d->from = Mailbox::find( imap()->mailboxName( d->fromName ) );
        if ( d->fromName.lower() == "inbox" )
            d->mrcInboxHack = true;
        d->to = Mailbox::find( d->toName, true );

        if ( !d->from )
            error( No, "No such mailbox: " + d->fromName );
        if ( d->to && !d->to->deleted() )
            error( No, "Mailbox already exists: " + d->toName );
    }

    if ( !d->fromPermissions )
        d->fromPermissions = new Permissions( d->from, imap()->user(), this );
    if ( !d->toPermissions )
        d->fromPermissions 
            = new Permissions( Mailbox::closestParent( imap()->mailboxName( d->toName ) ),
                               imap()->user(), this );

    if ( !d->fromPermissions->ready() || !d->toPermissions->ready() )
        return;

    if ( !d->mrcInboxHack &&
         !d->fromPermissions->allowed( Permissions::DeleteMailbox ) )
        error( No, "Not permitted to rename " + d->fromName );

    if ( !d->toPermissions->allowed( Permissions::CreateMailboxes ) )
        error( No, "Not permitted to create mailboxes under " + 
               d->toPermissions->mailbox()->name() );

    if ( !ok() )
        return;

    finish();
}
