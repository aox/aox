// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "view.h"

#include "mailbox.h"
#include "transaction.h"
#include "permissions.h"


class ViewData
    : public Garbage
{
public:
    ViewData()
        : parent( 0 ), ms( 0 ), mv( 0 ),
          p( 0 ), t( 0 ), q( 0 )
    {}

    String source;
    String view;

    Mailbox * parent;
    Mailbox * ms;
    Mailbox * mv;

    Permissions * p;
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
    d->view = astring();
    space();
    d->source = astring();
    Search::parse();
}

void View::execute()
{
    if ( !d->p ) {
        d->ms = Mailbox::find( imap()->mailboxName( d->source ) );
        if ( !d->ms || d->ms->synthetic() || d->ms->deleted() ) {
            error( No, "Can't create view on " + d->source );
            return;
        }

        d->parent = Mailbox::closestParent( imap()->mailboxName( d->view ) );
        if ( !d->parent ) {
            error( No, "Syntax error in view name: " + d->view );
            return;
        }

        d->p = new Permissions( d->parent, imap()->user(), this );
    }

    if ( !d->p->ready() )
        return;

    if ( !d->p->allowed( Permissions::CreateMailboxes ) ) {
        error( No, "Cannot create mailboxes under " + d->parent->name() );
        return;
    }

    if ( !d->t ) {
        d->mv = Mailbox::obtain( imap()->mailboxName( d->view ), true );
        if ( !d->mv ) {
            error( No, d->view + " is not a valid mailbox name" );
            return;
        }

        d->t = new Transaction( this );
        d->q = d->mv->create( d->t, imap()->user() );
        d->q = new Query( "insert into views "
                          "(view, selector, source, suidnext) values "
                          "((select id from mailboxes where name=$1),"
                          "$2, $3, 0)", this );
        d->q->bind( 1, imap()->mailboxName( d->view ) );
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

    OCClient::send( "mailbox " + d->mv->name().quoted() + " new" );

    finish();
}
