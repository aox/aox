// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "rename.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "occlient.h"
#include "permissions.h"
#include "transaction.h"


class RenameData
    : public Garbage
{
public:
    RenameData()
        : mrcInboxHack( false ), c( 0 ), t( 0 ), ready( false ) {}
public:
    String fromName;
    String toName;

    bool mrcInboxHack;
    Rename * c;
    Transaction * t;
    bool ready;

    class MailboxPair
        : public Garbage
    {
    public:
        MailboxPair()
            : from( 0 ), toParent( 0 ),
              fromPermissions( 0 ), toPermissions( 0 ),
              toUidvalidity( 0 ) {}
    public:
        Mailbox * from;
        String toName;
        Mailbox * toParent;
        Permissions * fromPermissions;
        Permissions * toPermissions;
        uint toUidvalidity;
    };

    List<MailboxPair> renames;

    void process( MailboxPair * p, MailboxPair * parent );
};


/*! \class Rename rename.h
    Renames a mailbox (RFC 3501 section 6.3.5) and its children.

    If the mailbox is named "inbox", we create create a new inbox
    after moving the old one, and ensure that mail is delivered to the
    new inbox henceforth, not to the renamed old one. This is more or
    less what RFC 3501 section 6.3.5 says.

    It's not clear what should happen if someone has inbox selected
    while it's being renamed. In our code, the renamed mailbox remains
    selected, and the new inbox is not selected.

    There is a race condition here: we check that the user has
    permission to carry out the transaction, but the permission
    checking is not within the transaction that does the move.  This
    seems to be insignificant - it can't be used to achieve anything.
*/


Rename::Rename()
    : d( new RenameData )
{
    d->c = this;
}


void Rename::parse()
{
    space();
    d->fromName = astring();
    if ( d->fromName.lower() == "inbox" )
        d->mrcInboxHack = true;
    space();
    d->toName = astring();
    end();
}


void RenameData::process( MailboxPair * p, MailboxPair * parent )
{
    p->fromPermissions = new Permissions( p->from, c->imap()->user(), c );
    if ( !parent || parent->toParent != p->toParent )
        p->toPermissions = new Permissions( p->toParent, c->imap()->user(), c );
    renames.append( p );

    String fn = c->imap()->mailboxName( p->toName );
    Mailbox * to = Mailbox::obtain( fn, false );
    if ( to && !to->deleted() ) {
        c->error( Rename::No, "Destination mailbox exists: " + p->toName );
        t->rollback();
        return;
    }
    p->toName = fn;

    // get rid of anything that may be in the way
    Query * q = 0;
    if ( to ) {
        q = new Query( "delete from mailboxes where id=$1", 0 );
        q->bind( 4, to->id() );
        t->enqueue( q );
        // and bump uidvalidity to inform any caches
        p->toUidvalidity = 1 + p->from->uidvalidity();
        if ( p->toUidvalidity <= to->uidvalidity() )
            p->toUidvalidity = 1 + to->uidvalidity();
    }

    // move the mailbox
    q = new Query( "update mailboxes set name=$1,uidvalidity=$2 "
                   "where id=$3", 0 );
    q->bind( 1, p->toName );
    q->bind( 2, p->toUidvalidity );
    q->bind( 3, p->from->id() );
    t->enqueue( q );

    // insert a deleted placeholder to ensure that uidnext/uidvalidity
    // will be okay if a new mailbox is created with the same name as
    // this one used to have
    q = new Query( "insert into mailboxes "
                   "(name,owner,uidnext,uidvalidity,deleted) "
                   "values ($1,$2,$3,$4,'t')", 0 );
    q->bind( 1, p->from->name() );
    q->bind( 2, c->imap()->user()->id() );
    q->bind( 3, p->from->uidnext() );
    q->bind( 4, p->from->uidvalidity() );
    t->enqueue( q );
}


void Rename::execute()
{
    if ( !d->t ) {
        d->t = new Transaction( this );
        if ( d->mrcInboxHack ) {
            // ensure that nothing's delivered to inbox during the move.
            Query * q = new Query( "select inbox from users "
                                   "where id=$1 "
                                   "for update", 0 );
            q->bind( 1, imap()->user()->id() );
            d->t->enqueue( q );
        }
    }

    if ( d->renames.isEmpty() ) {
        // 1. the first mailbox
        RenameData::MailboxPair * p = new RenameData::MailboxPair;
        p->from = Mailbox::find( imap()->mailboxName( d->fromName ) );
        if ( p->from == 0 ) {
            error( No, "No such mailbox: " + d->fromName );
            return;
        }
        p->toName = d->toName;
        p->toParent =
            Mailbox::closestParent( imap()->mailboxName( p->toName ) );
        d->process( p, 0 );

        // 2. for each mailbox, any children it may have.
        List<RenameData::MailboxPair>::Iterator it( d->renames );
        while ( it ) {
            Mailbox * m = it->from;
            List<Mailbox>::Iterator c( m->children() );
            while ( c ) {
                p = new RenameData::MailboxPair;
                p->from = c;
                p->toName = it->toName + c->name().mid( it->from->name().length() );
                d->process( p, it );
                ++c;
            }
            ++it;
        }
    }

    if ( !ok() )
        return;

    if ( d->mrcInboxHack ) {
        Query * q = new Query( "update users "
                               "set inbox=(select id from mailboxes where name=$1) "
                               "where id=$2", 0 );
        q->bind( 1, d->fromName );
        q->bind( 2, imap()->user()->id() );
        d->t->enqueue( q );
        q = new Query( "update mailboxes set deleted='f' where name=$1", 0 );
        q->bind( 1, d->fromName );
        d->t->enqueue( q );
    }

    // the transaction is now set up. let's see if we have permission
    // to carry it out.

    if ( !d->ready ) {
        List< RenameData::MailboxPair >::Iterator it( d->renames );
        while ( it ) {
            if ( !it->fromPermissions->ready() ||
                 !it->toPermissions->ready() )
                return;
            if ( !it->fromPermissions->allowed( Permissions::DeleteMailbox ) ) {
                error( No, "Not permitted to remove " + it->from->name() );
                break;
            }
            if ( it->toPermissions &&
                 !it->toPermissions->allowed( Permissions::CreateMailboxes ) )
            {
                error( No, "Not permitted to create " + it->toName );
                break;
            }
            ++it;
        }

        if ( !ok() )
            d->t->rollback();
        else
            d->t->commit();
        d->ready = true;
    }

    if ( !ok() || !d->t->done() )
        return;

    if ( d->t->failed() ) {
        error( No, "Database failure: " + d->t->error() );
        return;
    }

    List< RenameData::MailboxPair >::Iterator it( d->renames );
    while ( it ) {
        Mailbox * to = Mailbox::obtain( it->toName, true );
        Mailbox * from = it->from;
        to->setId( from->id() );
        to->setDeleted( false );
        to->setUidnext( from->uidnext() );
        to->setUidvalidity( it->toUidvalidity );
        from->setId( 0 );
        from->refresh();
        OCClient::send( "mailbox " + to->name().quoted() + " new" );
        if ( d->mrcInboxHack && from == imap()->user()->inbox() ) {
            OCClient::send( "mailbox " + from->name().quoted() + " new" );
        }
        else {
            from->setDeleted( true );
            OCClient::send( "mailbox " + from->name().quoted() + " deleted" );
        }
        ++it;
    }

    finish();
}    
