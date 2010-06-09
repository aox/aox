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
        : ThreadRootCreator::Message(), id( 0 ) {}

    EStringList references() const { return ids; }
    EString messageId() const { return mid; }

    void mergeThreads( uint, uint );

    EStringList ids;
    EString mid;

    uint id;
};


class UpdateDatabaseData
    : public Garbage
{
public:
    UpdateDatabaseData()
        : Garbage(), t( 0 ),
          findMessages( 0 ),
          threader( 0 ), base( 0 ),
          messages( 0 ),
          report( 0 ), temp( 0 ), update( 0 ),
          id1( 0 ), id2( 0 ),
          threading( true )
        {}

    Transaction * t;
    Query * findMessages;
    ThreadRootCreator * threader;
    BaseSubjectCreator * base;
    List<class DbMessage> * messages;

    Query * report;
    Query * temp;
    Query * update;

    uint id1;
    uint id2;

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
    : AoxCommand( args )
{
    d = 0;
}


void UpdateDatabase::execute()
{
    if ( !d->report ) {
        d->report
            = new Query(
                "select "
                "(select count(*) from messages where thread_root is null)"
                " as threadnull, "
                "(select count(*) from messages where base_subject is null)"
                " as basenull",
                this );
        d->report->execute();
    }
    if ( !d->report->done() )
        return;
    if ( d->report->hasResults() ) {
        Row * r = d->report->nextRow();
        printf( "Messages needing threading: %d.\n"
                "Messages needing subject classification: %d.\n",
                r->getInt( "threadnull" ),
                r->getInt( "basenull" ) );
    }

    if ( d->t && d->t->done() ) {
        if ( !d->t->failed() )
            error( "Transaction failed: " + d->t->error() );
        d->t = 0;
        if ( d->update && d->update->rows() )
            printf( "Processed %d messages.\nCommitted transaction.\n",
                    d->update->rows() );
    }

    end();

    if ( d->threading )
        thread();
    if ( !d->threading )
        subject();
}


void UpdateDatabase::thread()
{
    if ( !d->t ) {
        printf( "Looking for 32768 more messages to thread.\n" );
        d->t = new Transaction( this );
        d->findMessages
            = new Query( "select m.id, msgid.value as messageid, "
                         "ref.value as references "
                         "from messages m "
                         "left join header_fields msgid on (m.id=msgid.message and msgid.field=(select id from field_names where name='Message-Id')) "
                         "left join header_fields ref on (m.id=msgid.message and ref.field=(select id from field_names where name='References')) "
                         "where m.thread_root is null and m.id>$1"
                         "order by id limit 32768", this );
        d->findMessages->bind( 1, d->id1 );
        d->t->enqueue( d->findMessages );
        d->t->execute();
        d->messages = new List<DbMessage>();
        d->threader = 0;
        d->temp = 0;
        d->update = 0;
    }

    while ( d->findMessages->hasResults() ) {
        Row * r = d->findMessages->nextRow();
        DbMessage * m = new DbMessage;
        m->id = r->getInt( "id" );
        if ( m->id > d->id1 )
            d->id1 = m->id;
        if ( !r->isNull( "messageid" ) ) {
            m->mid = r->getEString( "messageid" );
        }
        if ( !r->isNull( "references" ) ) {
            AddressParser * ap
                = AddressParser::references( r->getEString( "references" ) );
            List<Address>::Iterator i( ap->addresses() );
            while ( i ) {
                if ( !i->lpdomain().isEmpty() )
                    m->ids.append( i->lpdomain() );
                ++i;
            }
        }
        if ( !m->mid.isEmpty() && m->ids.isEmpty() )
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
        d->threader = new ThreadRootCreator( d->messages, d->t );
        d->threader->execute();
        d->temp = new Query( "create temporary table md ("
                             "message integer,"
                             "messageid text,"
                             "thread_root integer"
                             ")", this );
        d->temp->enqueue( d->temp );
        d->t->execute();
    }

    if ( !d->temp->done() )
        return;

    if ( !d->update ) {
        Query * q = new Query( "copy md( messageid, thread_root ) "
                             "from stdin with binary", 0 );
        Dict<ThreadRootCreator::ThreadNode>::Iterator
            i( d->threader->nodes() );
        while ( i ) {
            ThreadRootCreator::Node * n = i;
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
            "where header_fields.id=13 and header_fields.value=messageid" );
        d->t->enqueue(
            "delete from md where message is null or message in ("
            "select id from messages m join md on (m.id=md.message)"
            " where m.thread_root is not null)" );

        // lock for nextmodseq in the right order
        d->t->enqueue( "select * from mailbox_messages "
                       "where id in ("
                       "select mm.mailbox from mailbox_messages mm "
                       "join md using (message)"
                       ") order by id for update" );
        // write the changes from the temptable
        d->update = new Query( "update messages set "
                               "thread_root=md.thread_root "
                               "from md "
                               "where id=md.message" );
        d->t->enqueue( d->update );
        // update modseq on all affected messages
        d->t->enqueue( "update mailbox_messages set "
                       "modseq=mb.nextmodseq "
                       "where message in (select message from md)" );
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


/*! Does all base subject computations. Subject is a verb, so this
    function is properly named by my very own standards. Even its
    name shows some frustration.
*/

void UpdateDatabase::subject()
{
    if ( !d->t ) {
        printf( "Looking for 32768 more messages to classify by subject.\n" );
        d->t = new Transaction( this );
        d->findMessages
            = new Query( "select m.id, s.value as subject "
                         "from messages m "
                         "left join header_fields s on (m.id=msgid.message and msgid.field=(select id from field_names where name='Subject')) "
                         "where m.base_subject is null and m.id>$1 "
                         "order by id limit 32768", this );
        d->findMessages->bind( 1, d->id2 );
        d->t->enqueue( d->findMessages );
        d->t->execute();
        d->messages = new List<DbMessage>();
        d->base = 0;
        d->temp = 0;
        d->update = 0;
    }

    while ( d->findMessages->hasResults() ) {
        Row * r = d->findMessages->nextRow();
        DbMessage * m = new DbMessage;
        m->id = r->getInt( "id" );
        if ( !r->isNull( "subject" ) )
            m->s = Message::baseSubject( r->getUString( "subject" ) );
        d->messages->append( m );
    }

    if ( !d->findMessages->done() )
        return;

    if ( !d->base ) {
        UStringList s;
        List<DbMessage>::Iterator i( d->messages );
        while ( i ) {
            s.append( m->s );
            ++i;
        }
        s.removeDuplicates();

    if ( s.isEmpty() ) {
        printf( "All messages are now classified by subject.\n" );
        d->t->commit();
        finish();
        return;
    }

        d->base = = new BaseSubjectCreator( s, d->t );
        d->base->execute();
        d->temp = new Query( "create temporary table md ("
                             "message integer,"
                             "base_subject integer"
                             ")", this );
        d->temp->enqueue( d->temp );
        d->t->execute();
    }

    if ( !d->temp->done() )
        return;

    if ( !d->update ) {
        Query * q = new Query( "copy md( message, base_subject ) "
                             "from stdin with binary", 0 );
        List<DbMessage>::Iterator i( d->messages );
        while ( i ) {
            uint bsid = d->base->id( m->s );
            if ( bsid > 0 ) {
                q->bind( 1, i->id );
                q->bind( 2, d->base->id( m->s ) );
                q->submitLine();
                if ( i->id > d->id2 )
                    d->id2 = i->id;
            }
            ++i;
        }
        d->t->enqueue( q );

        // lock for nextmodseq in the right order
        d->t->enqueue( "select * from mailbox_messages "
                       "where id in ("
                       "select mm.mailbox from mailbox_messages mm "
                       "join md using (message)"
                       ") order by id for update" );
        // write the changes from the temptable
        d->update = new Query( "update messages set "
                               "base_subject=md.base_subject "
                               "from md "
                               "where id=md.message" );
        d->t->enqueue( d->update );
        // update modseq on all affected messages
        d->t->enqueue( "update mailbox_messages set "
                       "modseq=mb.nextmodseq "
                       "where message in (select message from md)" );
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
