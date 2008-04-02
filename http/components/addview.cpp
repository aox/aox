// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addview.h"

#include "link.h"
#include "http.h"
#include "query.h"
#include "htmlform.h"
#include "selector.h"
#include "frontmatter.h"
#include "httpsession.h"
#include "transaction.h"
#include "permissions.h"
#include "occlient.h"
#include "mailbox.h"
#include "webpage.h"
#include "query.h"
#include "user.h"


class AddViewData
    : public Garbage
{
public:
    AddViewData()
        : form( 0 ), ms( 0 ), mv( 0 ), selector( 0 ),
          t( 0 ), q( 0 )
    {}

    HtmlForm * form;
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
        d->form = form();
        d->form->setValuesFrom( page() );

        if ( !d->form->filled() ) {
            setContents( "" );
            return;
        }
        else {
            UString v( d->form->getValue( "view" ) );
            d->view = page()->user()->mailboxName( v );

            UString s( d->form->getValue( "source" ) );
            UString source( page()->user()->mailboxName( s ) );

            Mailbox * parent = Mailbox::closestParent( d->view );
            if ( !parent ) {
                setContents( "Invalid view name." );
                return;
            }

            d->ms = Mailbox::obtain( source, false );
            if ( !d->ms || d->ms->synthetic() || d->ms->deleted() ) {
                setContents( "Invalid source name." );
                return;
            }

            UString sel( d->form->getValue( "selector" ) );
            d->selector = Selector::fromString( sel.utf8() );
            if ( !d->selector ) {
                setContents( "Invalid selector." );
                return;
            }

            page()->requireRight( parent, Permissions::CreateMailboxes );
        }
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
        d->t->enqueue( d->mv->refresh() );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        setContents( d->t->error() );
    }
    else {
        OCClient::send( "mailbox " + d->mv->name().utf8().quoted() + " new" );
        d->form->clear();
        setContents( "OK" );
    }
}


/*! This private helper function returns a pointer to a form with all
    the fields necessary for view creation. */

HtmlForm * AddView::form() const
{
    Link * l = new Link;
    l->setType( Link::Webmail );
    l->setViews( true );
    l->setSuffix( Link::AddObject );
    HtmlForm * f = new HtmlForm( l->canonical() );
    f->requireField( "view" );
    f->requireField( "source" );
    f->requireField( "selector" );
    f->addField( "addview", "submit", "Add View" );
    return f;
}


/*! Appends a form() to the component's output \a t if it's being viewed
    through the /webmail/views page, and calls setContents(). */

void AddView::setContents( const String & t )
{
    String s;

    if ( page()->link()->suffix() != Link::AddObject ) {
        s.append( "<p>" );
        s.append( t );
        s.append( d->form->html() );
    }
    else {
        if ( t.isEmpty() )
            s.append( "Please fill in the required fields." );
        else
            s.append( t );
    }

    PageComponent::setContents( s );
}
