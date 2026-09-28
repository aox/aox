// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "obliterator.h"

#include "runner.h"
#include "client.h"

#include "transaction.h"
#include "eventloop.h"
#include "mailbox.h"
#include "buffer.h"
#include "query.h"

#include <stdio.h>
#include <stdlib.h>


class ObliteratorWaiter
    : public Connection
{
public:
    ObliteratorWaiter( Obliterator * ob): Connection(), o( ob ) {}
    void react( Event ) {
        o->execute();
    }
    Obliterator * o;
};



/*!  Constructs an Obliterator which will obliterate all mail
     belonging to \a loginName and then tell \a runner to send more
     data (TestRunner::send()).
*/

Obliterator::Obliterator( TestRunner * runner, const EString & loginName )
    : EventHandler(),
      ln( loginName ), ao( 0 ), t( 0 ), r( runner ), w( 0 )
{
    w = new ObliteratorWaiter( this );
    w->connect( Endpoint( TestClient::serverAddress(), 143 ) );
    EventLoop::global()->addConnection( w );
    t = new Transaction( this );
    ao = new Query( "select allow_obliteration from mailstore", this );
    t->enqueue( ao );
    t->execute();
}


void Obliterator::execute()
{
    if ( ao ) {
        if ( w->state() == Connection::Connecting )
            return;
        if ( !ao->done() )
            return;
        Row * r = ao->nextRow();
        if ( ao->failed() || !r || !r->getBoolean( "allow_obliteration" ) ) {
            fprintf( stderr, "Database does not want to be obliterated.\n" );
            exit( -1 );
        }
        ao = 0;

        Query * q;

        q = new Query( "select id from mailboxes for update", this );
        t->enqueue( q );

        q = new Query( "delete from aliases "
                       "where id not in (select alias from users)", this );
        t->enqueue( q );

        q = new Query( "update aliases set mailbox="
                       "(select id from mailboxes"
                       " where lower(name)=lower('/users/'||"
                       " (select login from users where alias=aliases.id)"
                       " ||'/INBOX'))", 0 );
        t->enqueue( q );

        q = new Query( "truncate delivery_recipients, deliveries, "
                       "messages, mailbox_messages, deleted_messages, "
                       "scripts, fileinto_targets, annotations, "
                       "subscriptions, flags, thread_roots, "
                       "date_fields, address_fields, header_fields, "
                       "part_numbers, bodyparts, unparsed_messages, "
                       "autoresponses, thread_indexes", 0 );
        t->enqueue( q );

        q = new Query( "alter sequence messages_id_seq restart with 1", 0 );
        t->enqueue( q );

        q = new Query( "alter sequence thread_roots_id_seq restart with 1", 0 );
        t->enqueue( q );

        q = new Query( "delete from field_names where id>32", 0 );
        t->enqueue( q );

        q = new Query( "delete from flag_names where id>5", 0 );
        t->enqueue( q );

        q = new Query( "delete from annotation_names", 0 );
        t->enqueue( q );

        q = new Query( "delete from addresses where id not in "
                       "(select address from aliases)", 0 );
        t->enqueue( q );

        q = new Query( "delete from permissions where mailbox in "
                       "(select id from mailboxes where owner is not null)",
                       0 );
        t->enqueue( q );

        q = new Query( "delete from mailboxes "
                       "where owner is not null and id not in "
                       "(select mailbox from aliases)", 0 );
        t->enqueue( q );

        q = new Query( "select setval('nextmodseq', 2, false)", 0 );
        t->enqueue( q );

        q = new Query( "update mailboxes set "
                       "uidnext=1,nextmodseq=2,"
                       "first_recent=1,uidvalidity=1,"
                       "deleted='f'", 0 );
        t->enqueue( q );

        q = new Query( "update mailboxes set owner=("
                       "select u.id from users u "
                       "join aliases a on (u.alias=a.id) "
                       "where a.mailbox=mailboxes.id) "
                       "where name ilike '/users/%'", 0 );
        t->enqueue( q );

        q = new Query( "delete from mailboxes "
                       "where owner is null and name ilike '/users/%'", 0 );
        t->enqueue( q );

        // mailboxes that survive obliteration keep their ids, and some of
        // them may be above 2000 already, so we cannot just restart at a
        // constant: the next create would collide.
        q = new Query( "select setval('mailboxes_id_seq',"
                       " greatest(2000, (select max(id) from mailboxes)))",
                       0 );
        t->enqueue( q );

        q = new Query( "notify obliterated", 0 );
        t->enqueue( q );
        t->commit();
    }

    if ( !t->done() )
        return;

    if ( w->state() == Connection::Connected )
        return;

    if ( t->failed() )
        fprintf( stderr, "Obliterate failed: %s\n", t->error().cstr() );
    else
        r->send();
}


/*! Returns true if the Obliterator has done its work, and false if
    it's still working.
*/

bool Obliterator::done() const
{
    return t->done() && w->state() != Connection::Connected;
}


/*! Returns the error string if obliteration failed, and an empty
    string if it hasn't failed (yet).
*/

EString Obliterator::error() const
{
    return t->error();
}
