// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addview.h"

#include "link.h"
#include "http.h"
#include "query.h"
#include "selector.h"
#include "frontmatter.h"
#include "httpsession.h"
#include "transaction.h"
#include "permissions.h"
#include "mailbox.h"
#include "webpage.h"
#include "user.h"


class AddViewData
    : public Garbage
{
public:
    AddViewData()
        : ms( 0 ), mv( 0 ), selector( 0 ),
          t( 0 ), q( 0 )
    {}

    UString view;
    Mailbox * ms;
    Mailbox * mv;
    Selector * selector;
    Transaction * t;
    Query * q;
};


/*! \class AddView addview.h
    Allows the user to create a new view.
*/

AddView::AddView()
    : PageComponent( "addview" )
{
}


void AddView::execute()
{
    if ( !d ) {
        d = new AddViewData;
        page()->requireUser();
    }

    if ( !page()->permitted() )
        return;

    if ( !d->ms ) {
        UString v( page()->parameter( "view" ) );
        UString s( page()->parameter( "source" ) );
        UString sel( page()->parameter( "selector" ) );

        d->view = page()->user()->mailboxName( v );

        Mailbox * parent = Mailbox::closestParent( d->view );
        if ( !parent ) {
            setContents( "Invalid view name." );
            return;
        }

        UString source( page()->user()->mailboxName( s ) );
        d->ms = Mailbox::obtain( source, false );
        if ( !d->ms || d->ms->deleted() ) {
            setContents( "Invalid source name." );
            return;
        }

        d->selector = Selector::fromString( sel.utf8() );
        if ( !d->selector ) {
            setContents( "Invalid selector." );
            return;
        }

        page()->requireRight( parent, Permissions::CreateMailboxes );
    }

    if ( !page()->permitted() )
        return;

    if ( !d->t ) {
        d->mv = Mailbox::obtain( d->view, true );
        if ( !d->mv ) {
            setContents( "Invalid view name." );
            return;
        }

        d->t = new Transaction( this );
        d->q = d->mv->create( d->t, page()->link()->server()->user() );
        d->q = new Query(
            "insert into views "
            "(view, selector, source, nextmodseq) values "
            "((select id from mailboxes where name=$1),$2,$3,1::bigint)",
            this
        );
        d->q->bind( 1, d->view );
        d->q->bind( 2, d->selector->string() );
        d->q->bind( 3, d->ms->id() );
        d->t->enqueue( d->q );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        setContents( d->t->error() );
    }
    else {
        setContents( "OK" );
    }
}
