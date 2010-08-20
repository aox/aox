// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "updatedb.h"

#include "md5.h"
#include "utf.h"
#include "dict.h"
#include "query.h"
#include "ustring.h"
#include "address.h"
#include "transaction.h"
#include "helperrowcreator.h"

#include <stdio.h>
#include <stdlib.h>


class DbMessage
    : public ThreadRootCreator::Message
{
public:
    DbMessage()
        : ThreadRootCreator::Message(), id( 0 ), t( 0 ) {}

    EStringList references() const { return ids; }
    EString messageId() const { return mid; }

    void mergeThreads( uint, uint );

    EStringList ids;
    EString mid;
    UString s;

    uint id;
    Transaction * t;
};


class UpdateDatabaseData
    : public Garbage
{
public:
    UpdateDatabaseData()
        : Garbage(), t( 0 ),
          findMessages( 0 ),
          threader( 0 ),
          messages( 0 ),
          report( 0 ), temp( 0 ), update( 0 ),
          sofar( 0 ), threading( true )
        {}

    Transaction * t;
    Query * findMessages;
    ThreadRootCreator * threader;
    List<ThreadRootCreator::Message> * messages;

    Query * report;
    Query * temp;
    Query * update;

    uint sofar;

    bool threading;
};


static AoxFactory<UpdateDatabase>
f( "update", "database", "Update the database contents.",
   "    Synopsis: aox update database\n\n"
   "    Performs any updates to the database contents which are too\n"
   "    slow for inclusion in \"aox upgrade schema\". This command is\n"
   "    meant to be used while the server is running. It does its\n"
   "    work in small chunks, so it can be restarted at any time,\n"
   "    and is tolerant of interruptions.\n" );


/*! \class UpdateDatabase updatedb.h
    This class handles the "aox update database" command.
*/

UpdateDatabase::UpdateDatabase( EStringList * args )
    : AoxCommand( args ), d( new UpdateDatabaseData )
{
}


void UpdateDatabase::execute()
{
    if ( !d->threading )
        return;

    if ( !d->report ) {
        database( true );
        d->report
            = new Query( "select count(*)::integer as threadnull "
                         "from messages where thread_root is null",
                         this );
        d->report->execute();
    }
    if ( !d->report->done() )
        return;
    if ( d->report->hasResults() ) {
        Row * r = d->report->nextRow();
        printf( "Messages needing threading: %d.\n",
                r->getInt( "threadnull" ) );
    }

    if ( d->t && d->t->done() ) {
        if ( d->t->failed() )
            error( "Transaction failed: " + d->t->error() );
        d->t = 0;
        if ( d->update && d->update->rows() )
            printf( "Processed %d messages.\nCommitted transaction.\n",
                    d->update->rows() );
    }

    end();

    if ( !d->t ) {
        printf( "Looking for 32768 more messages to thread.\n" );
        d->t = new Transaction( this );
        d->findMessages
            = new Query( "select m.id, msgid.value as messageid, "
                         "ref.value as references "
                         "from messages m "
                         "left join header_fields msgid on"
                         " (m.id=msgid.message and msgid.field=$2 and msgid.part='') "
                         "left join header_fields ref on"
                         " (m.id=ref.message and ref.field=$3 and ref.part='') "
                         "where m.thread_root is null and m.id>$1 "
                         "order by id limit 32768", this );
        d->findMessages->bind( 1, d->sofar );
        d->findMessages->bind( 2, HeaderField::MessageId );
        d->findMessages->bind( 3, HeaderField::References );
        d->t->enqueue( d->findMessages );
        d->t->execute();
        d->messages = new List<ThreadRootCreator::Message>();
        d->threader = 0;
        d->temp = 0;
        d->update = 0;
    }

    while ( d->findMessages->hasResults() ) {
        Row * r = d->findMessages->nextRow();
        DbMessage * m = new DbMessage;
        m->id = r->getInt( "id" );
        m->t = d->t;
        if ( m->id > d->sofar )
            d->sofar = m->id;
        if ( !r->isNull( "messageid" ) ) {
            m->mid = r->getEString( "messageid" );
        }
        if ( !r->isNull( "references" ) ) {
            AddressParser * ap
                = AddressParser::references( r->getEString( "references" ) );
            List<Address>::Iterator i( ap->addresses() );
            while ( i ) {
                if ( !i->lpdomain().isEmpty() )
                    m->ids.append( "<" + i->lpdomain() + ">" );
                ++i;
            }
        }
        if ( !m->mid.isEmpty() )
            d->messages->append( m );
    }

    if ( !d->findMessages->done() )
        return;

    if ( d->messages->isEmpty() ) {
        d->threading = false;
        printf( "All messages are now threaded.\n" );
        finish();
        return;
    }

    if ( !d->threader ) {
        printf( "%s",
                ("Threading " + fn( d->messages->count() ) +
                 " messages.\n").cstr() );
        d->threader = new ThreadRootCreator( d->messages, d->t );
        d->threader->execute();
        d->temp = new Query( "create temporary table md ("
                             "message integer,"
                             "messageid text,"
                             "thread_root integer"
                             ")", this );
        d->t->enqueue( d->temp );
        d->t->execute();
    }

    if ( !d->temp->done() )
        return;

    if ( !d->update ) {
        Query * q = new Query( "copy md( messageid, thread_root ) "
                             "from stdin with binary", 0 );
        Dict<ThreadRootCreator::ThreadNode>::Iterator
            i( d->threader->threadNodes() );
        while ( i ) {
            ThreadRootCreator::ThreadNode * n = i;
            q->bind( 1, n->id );
            while ( n->parent )
                n = n->parent;
            q->bind( 2, n->trid );
            q->submitLine();
            ++i;
        }
        d->t->enqueue( q );

        // update the md table to refer to extant messages ONLY
        d->t->enqueue(
            "update md set message=header_fields.message "
            "from header_fields "
            "where header_fields.field=13 and header_fields.value=messageid" );
        d->t->enqueue(
            "delete from md where message is null or message in ("
            "select id from messages m join md on (m.id=md.message)"
            " where m.thread_root is not null)" );

        // lock for nextmodseq in the right order
        d->t->enqueue( "select * from mailboxes "
                       "where id in ("
                       "select mm.mailbox from mailbox_messages mm "
                       "join md using (message)"
                       ") order by id for update" );
        // write the changes from the temptable
        d->update = new Query( "update messages set "
                               "thread_root=md.thread_root "
                               "from md "
                               "where id=md.message", this );
        d->t->enqueue( d->update );
        // update modseq on all affected messages
        d->t->enqueue( "update mailbox_messages "
                       "set modseq=mailboxes.nextmodseq "
                       "from md, mailboxes "
                       "where mailbox_messages.message=md.message "
                       "and mailbox=mailboxes.id" );
        // ... and the mailboxes' nextmodseq
        d->t->enqueue( "update mailboxes set nextmodseq=nextmodseq+1 "
                       "where id in ("
                       "select mm.mailbox from mailbox_messages mm "
                       "join md using (message)"
                       ")" );
        d->t->enqueue( "notify mailboxes_updated" );
        d->t->enqueue( "drop table md" );
        d->t->commit();
    }
}

void DbMessage::mergeThreads( uint to, uint from )
{
    Query * q;
    q = new Query( "update messages set thread_root=$1 "
                   "where thread_root=$2", 0 );
    q->bind( 1, to );
    q->bind( 1, from );
    t->enqueue( q );
    q = new Query( "delete from thread_roots where id=$1", 0 );
    q->bind( 1, from );
    t->enqueue( q );
}
