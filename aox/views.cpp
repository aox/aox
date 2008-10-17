// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "views.h"

#include "utf.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "selector.h"
#include "transaction.h"
#include "searchsyntax.h"
#include "addresscache.h"


class CreateViewData
    : public Garbage
{
public:
    CreateViewData()
        : user( 0 ), mv( 0 ), ms( 0 ), selector( 0 ), t( 0 )
    {}

    UString name;
    UString source;
    User * user;
    Mailbox * mv;
    Mailbox * ms;
    Selector * selector;
    Transaction * t;
};


/*! \class CreateView views.h
    This class handles the "aox add view" command.
*/

CreateView::CreateView( StringList * args )
    : AoxCommand( args ), d( new CreateViewData )
{
}


void CreateView::execute()
{
    if ( d->name.isEmpty() ) {
        parseOptions();
        Utf8Codec c;
        d->name = c.toUnicode( next() );
        d->source = c.toUnicode( next() );
        UString owner( c.toUnicode( next() ) );
        d->selector = parseSelector( args() );

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( d->name.isEmpty() )
            error( "No name supplied for the view." );
        if ( d->source.isEmpty() )
            error( "No source mailbox name supplied." );
        if ( !d->selector )
            error( "Invalid search expression supplied." );

        database( true );
        AddressCache::setup();
        Mailbox::setup( this );

        if ( !owner.isEmpty() ) {
            d->user = new User;
            d->user->setLogin( owner );
            d->user->refresh( this );
        }
    }

    if ( !choresDone() )
        return;

    if ( !d->t ) {
        if ( d->user ) {
            if ( d->user->state() == User::Unverified )
                return;

            if ( d->user->state() == User::Nonexistent )
                error( "No user named " + d->user->login().utf8() );

            if ( !d->name.startsWith( "/" ) )
                d->name = d->user->home()->name() + "/" + d->name;

            if ( !d->source.startsWith( "/" ) )
                d->source = d->user->home()->name() + "/" + d->source;
        }

        d->ms = Mailbox::obtain( d->source );
        if ( !d->ms || d->ms->synthetic() || d->ms->deleted() )
            error( "Can't create view on " + d->source.utf8() );

        d->mv = Mailbox::obtain( d->name );
        if ( !d->mv || !( d->mv->synthetic() || d->mv->deleted() ) )
            error( "Can't create view named " + d->name.utf8() );

        d->t = new Transaction( this );

        Query * q = d->mv->create( d->t, d->user );
        if ( !q )
            error( "Couldn't create view named " + d->name.utf8() );

        q = new Query( "insert into views "
                       "(view, selector, source, nextmodseq) values "
                       "((select id from mailboxes where name=$1),"
                       "$2, $3, 1::bigint)", this );
        q->bind( 1, d->name );
        q->bind( 2, d->selector->string() );
        q->bind( 3, d->ms->id() );
        d->t->enqueue( q );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't create view" );

    finish();
}
