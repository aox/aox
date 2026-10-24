// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "updatedb.h"

#include "md5.h"
#include "utf.h"
#include "dict.h"
#include "mover.h"
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
          messages( 0 ), byMessageId( 0 ),
          report( 0 ), temp( 0 ), update( 0 ),
          sofar( 0 ), threading( true ),
          subjectReport( 0 ), findSubjects( 0 ),
          subjectTemp( 0 ), subjectUpdate( 0 ),
          subjectSofar( 0 ), subjects( true ),
          findAllMail( 0 ), fillMs( 0 ), fill( 0 ),
          allMailboxes( 0 ), allmail( true )
        {}

    class AllMail
        : public Garbage
    {
    public:
        AllMail(): owner( 0 ) {}
        UString name;
        uint owner;
    };

    Transaction * t;
    Query * findMessages;
    ThreadRootCreator * threader;
    List<ThreadRootCreator::Message> * messages;
    Dict<DbMessage> * byMessageId;

    Query * report;
    Query * temp;
    Query * update;

    uint sofar;

    bool threading;

    Query * subjectReport;
    Query * findSubjects;
    Query * subjectTemp;
    Query * subjectUpdate;
    List<DbMessage> * subjectMessages;

    uint subjectSofar;

    bool subjects;

    Query * findAllMail;
    Query * fillMs;
    Query * fill;
    List<UpdateDatabaseData::AllMail> * allMailboxes;
    bool allmail;
};


static AoxFactory<UpdateDatabase>
f( "update", "database", "Update the database contents.",
   "    Synopsis: aox update database\n\n"
   "    Performs any updates to the database contents which are too\n"
   "    slow for inclusion in \"aox upgrade schema\". This command is\n"
   "    meant to be used while the server is running. It does its\n"
   "    work in small chunks, so it can be restarted at any time,\n"
   "    and is tolerant of interruptions.\n\n"
   "    With -n it reports what it would do to the all mail\n"
   "    mailboxes, and rolls that back instead of committing.\n" );


/*! \class UpdateDatabase updatedb.h
    This class handles the "aox update database" command.
*/

UpdateDatabase::UpdateDatabase( EStringList * args )
    : AoxCommand( args ), d( new UpdateDatabaseData )
{
}


void UpdateDatabase::execute()
{
    if ( !d->threading ) {
        // each phase hands over to the next when it runs out of work,
        // and every wake-up has to reach the phase that is waiting
        if ( d->subjects )
            backfillSubjects();
        else
            fillAllMail();
        return;
    }

    if ( !d->report ) {
        parseOptions();
        end();
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
        printf( "Messages that might need threading: %d.\n",
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

    if ( !d->t ) {
        printf( "Looking for 4096 more messages to thread.\n" );
        d->t = new Transaction( this );
        d->findMessages
            = new Query( "select m.id, msgid.value as messageid, "
                         "ref.value as references "
                         "from messages m "
                         "join header_fields msgid on"
                         " (m.id=msgid.message and msgid.field=$2 and msgid.part='') "
                         "left join header_fields ref on"
                         " (m.id=ref.message and ref.field=$3 and ref.part='') "
                         "where m.thread_root is null and m.id>$1 "
                         "order by id limit 4096", this );
        d->findMessages->bind( 1, d->sofar );
        d->findMessages->bind( 2, HeaderField::MessageId );
        d->findMessages->bind( 3, HeaderField::References );
        d->t->enqueue( d->findMessages );
        d->t->execute();
        d->messages = new List<ThreadRootCreator::Message>();
        d->byMessageId = new Dict<DbMessage>();
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
            d->byMessageId->insert( m->mid, m );
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
        d->t = 0;
        backfillSubjects();
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
                             ") on commit drop", this );
        d->t->enqueue( d->temp );
        d->t->execute();
    }

    if ( !d->temp->done() )
        return;

    if ( !d->update ) {
        Query * q = new Query( "copy md( message, messageid, thread_root ) "
                             "from stdin with binary", 0 );
        Dict<ThreadRootCreator::ThreadNode>::Iterator
            i( d->threader->threadNodes() );
        while ( i ) {
            ThreadRootCreator::ThreadNode * n = i;
            DbMessage * m = d->byMessageId->find( n->id );
            if ( m ) {
                q->bind( 1, m->id );
                q->bind( 2, n->id );
                while ( n->parent )
                    n = n->parent;
                q->bind( 3, n->trid );
                q->submitLine();
            }
            ++i;
        }
        d->t->enqueue( q );

        // occasionally messages are duplicated. thread all duplicates.
        d->t->enqueue( "insert into md( message, messageid, thread_root ) "
                       "select m.id, md.messageid, md.thread_root"
                       "  from messages m"
                       "  join header_fields hf on"
                       "   (m.id=hf.message and hf.field=13 and hf.part='')"
                       "  join md on (hf.value=md.messageid)"
                       "  where m.id!=md.message and m.thread_root is null" );

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
        // one modseq for the whole update, shared by every mailbox
        d->t->enqueue( "select nextval('nextmodseq')" );
        // update modseq on all affected messages
        d->t->enqueue( "update mailbox_messages "
                       "set modseq=currval('nextmodseq') "
                       "from md "
                       "where mailbox_messages.message=md.message" );
        // ... and the mailboxes' nextmodseq
        d->t->enqueue( "update mailboxes "
                       "set nextmodseq=currval('nextmodseq')+1 "
                       "where id in ("
                       "select mm.mailbox from mailbox_messages mm "
                       "join md using (message)"
                       ")" );
        d->t->enqueue( "notify mailboxes_updated" );
        d->t->commit();
    }
}


/*! Fills in messages.base_subject for messages injected before that
    column existed. RFC5256's base subject needs 144 lines of C++ in
    Message::baseSubject(), so we fetch subjects, compute, and write
    back, 4096 messages at a time.

    No modseq is bumped: base_subject changes how SORT (SUBJECT)
    orders messages, but no client can fetch it, so there is nothing
    for a client to have cached wrongly.
*/

void UpdateDatabase::backfillSubjects()
{
    if ( !d->subjects )
        return;

    if ( !d->subjectReport ) {
        database( true );
        d->subjectReport
            = new Query( "select count(*)::integer as nobase "
                         "from messages where base_subject is null",
                         this );
        d->subjectReport->execute();
    }
    if ( !d->subjectReport->done() )
        return;
    if ( d->subjectReport->hasResults() ) {
        Row * r = d->subjectReport->nextRow();
        printf( "Messages that need a base subject: %d.\n",
                r->getInt( "nobase" ) );
    }

    if ( d->t && d->t->done() ) {
        if ( d->t->failed() )
            error( "Transaction failed: " + d->t->error() );
        d->t = 0;
        if ( d->subjectUpdate && d->subjectUpdate->rows() )
            printf( "Gave %d messages a base subject.\n"
                    "Committed transaction.\n",
                    d->subjectUpdate->rows() );
    }

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->findSubjects
            = new Query( "select m.id, "
                         "(select hf.value from header_fields hf "
                         " where hf.message=m.id and hf.part='' "
                         " and hf.field=$2 "
                         " order by hf.position limit 1) as subject "
                         "from messages m "
                         "where m.base_subject is null and m.id>$1 "
                         "order by m.id limit 4096", this );
        d->findSubjects->bind( 1, d->subjectSofar );
        d->findSubjects->bind( 2, HeaderField::Subject );
        d->t->enqueue( d->findSubjects );
        d->subjectTemp
            = new Query( "create temporary table bs ("
                         "message integer,"
                         "base_subject text"
                         ") on commit drop", this );
        d->t->enqueue( d->subjectTemp );
        d->t->execute();
        d->subjectMessages = new List<DbMessage>;
        d->subjectUpdate = 0;
    }

    while ( d->findSubjects->hasResults() ) {
        Row * r = d->findSubjects->nextRow();
        DbMessage * m = new DbMessage;
        m->id = r->getInt( "id" );
        if ( m->id > d->subjectSofar )
            d->subjectSofar = m->id;
        if ( !r->isNull( "subject" ) )
            m->s = Message::baseSubject( r->getUString( "subject" ) );
        d->subjectMessages->append( m );
    }

    if ( !d->findSubjects->done() || !d->subjectTemp->done() )
        return;

    if ( d->subjectMessages->isEmpty() ) {
        d->subjects = false;
        printf( "All messages now have a base subject.\n" );
        d->t = 0;
        fillAllMail();
        return;
    }

    if ( !d->subjectUpdate ) {
        Query * q = new Query( "copy bs( message, base_subject ) "
                               "from stdin with binary", 0 );
        List<DbMessage>::Iterator i( d->subjectMessages );
        while ( i ) {
            q->bind( 1, i->id );
            q->bind( 2, i->s );
            q->submitLine();
            ++i;
        }
        d->t->enqueue( q );
        d->subjectUpdate = new Query( "update messages set "
                                      "base_subject=bs.base_subject "
                                      "from bs where id=bs.message", this );
        d->t->enqueue( d->subjectUpdate );
        d->t->commit();
    }
}


/*! Adds whatever is missing to each all mail mailbox. A mailbox can
    be short of messages because it was created before its owner's
    mail arrived, or because a delivery happened in a process that had
    not yet heard about the mailbox.
*/

void UpdateDatabase::fillAllMail()
{
    if ( !d->allmail )
        return;

    if ( !d->findAllMail ) {
        database( true );
        d->findAllMail = new Query( "select name, owner from mailboxes "
                                    "where lower(flag)='\\all' and not deleted "
                                    "and owner is not null "
                                    "order by id", this );
        d->findAllMail->execute();
        d->allMailboxes = new List<UpdateDatabaseData::AllMail>;
    }

    while ( d->findAllMail->hasResults() ) {
        Row * r = d->findAllMail->nextRow();
        UpdateDatabaseData::AllMail * m = new UpdateDatabaseData::AllMail;
        m->name = r->getUString( "name" );
        m->owner = r->getInt( "owner" );
        d->allMailboxes->append( m );
    }

    if ( !d->findAllMail->done() )
        return;

    if ( d->t && d->t->done() ) {
        if ( d->t->failed() )
            error( "Transaction failed: " + d->t->error() );
        d->t = 0;
        uint n = 0;
        if ( d->fill )
            n = d->fill->rows();
        UpdateDatabaseData::AllMail * m = d->allMailboxes->firstElement();
        if ( opt( 'n' ) > 0 ) {
            // nothing was committed, so looking again would find the
            // same messages missing for ever
            printf( "Would add %d messages to %s.\n",
                    n, m->name.utf8().cstr() );
            d->allMailboxes->shift();
        }
        else if ( n ) {
            printf( "Added %d messages to %s.\n",
                    n, m->name.utf8().cstr() );
        }
        else {
            d->allMailboxes->shift();
        }
        d->fill = 0;
        d->fillMs = 0;
    }

    if ( d->allMailboxes->isEmpty() ) {
        d->allmail = false;
        printf( "All mail mailboxes now hold their owners' mail.\n" );
        finish();
        return;
    }

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->fillMs = new Query( "select nextval('nextmodseq') as nextmodseq",
                               this );
        d->t->enqueue( d->fillMs );
        d->t->execute();
    }

    if ( !d->fillMs->done() )
        return;

    if ( !d->fill ) {
        Row * r = d->fillMs->nextRow();
        if ( !r )
            error( "Could not allocate a modseq" );
        UpdateDatabaseData::AllMail * m = d->allMailboxes->firstElement();
        d->fill = Mover::fillAllMail( d->t, m->name, m->owner,
                                      r->getBigint( "nextmodseq" ), 4096 );
        if ( opt( 'n' ) > 0 )
            d->t->rollback();
        else
            d->t->commit();
    }
}
