// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "view.h"

#include "mailbox.h"
#include "occlient.h"
#include "transaction.h"


class ViewData
    : public Garbage
{
public:
    ViewData()
        : parent( 0 ), ms( 0 ), mv( 0 ),
          t( 0 ), q( 0 )
    {}

    UString view;

    Mailbox * parent;
    Mailbox * ms;
    Mailbox * mv;

    Transaction * t;
    Query * q;
};


/*! \class View view.h
    ...
*/

View::View()
    : Search( false ),
      d( new ViewData )
{
    setGroup( 0 );
}


void View::parse()
{
    space();
    require( "create" );
    space();
    d->view = mailboxName();
    space();
    d->ms = mailbox();
    Search::parse();
}

void View::execute()
{
    if ( state() != Executing )
        return;

    if ( !d->parent ) {
        d->parent = Mailbox::closestParent( d->view );
        if ( !d->parent ) {
            error( No, "Syntax error in view name: " + d->view.ascii() );
            return;
        }

        requireRight( d->parent, Permissions::CreateMailboxes );
    }

    if ( !permitted() )
        return;

    if ( !d->t ) {
        d->mv = Mailbox::obtain( d->view, true );
        if ( !d->mv ) {
            error( No, d->view.ascii() + " is not a valid mailbox name" );
            return;
        }

        d->t = new Transaction( this );
        d->q = d->mv->create( d->t, imap()->user() );
        d->q = new Query( "insert into views "
                          "(view, selector, source, nextmodseq) values "
                          "((select id from mailboxes where name=$1),"
                          "$2, $3, 1::bigint)", this );
        d->q->bind( 1, d->view );
        d->q->bind( 2, selector()->string() );
        d->q->bind( 3, d->ms->id() );
        d->t->enqueue( d->q );
        d->t->enqueue( d->mv->refresh() );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( No, "Database error: " + d->t->error() );

    OCClient::send( "mailbox " + d->mv->name().utf8().quoted() + " new" );

    finish();
}
