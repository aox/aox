// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "reparse.h"

#include "file.h"
#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "injector.h"
#include "fieldcache.h"
#include "transaction.h"
#include "addresscache.h"

#include <stdio.h>
#include <sys/stat.h> // mkdir
#include <sys/types.h> // mkdir
#include <unistd.h> // getpid


class ReparseData
    : public Garbage
{
public:
    ReparseData()
        : q( 0 ), row( 0 ), injector( 0 ), t( 0 ),
          msg( 0 ), m( 0 )
    {}

    Query * q;
    Row * row;
    Injector * injector;
    Transaction * t;
    Message * msg;
    Mailbox * m;
};


/*! \class Reparse reparse.h
    This class handles the "aox reparse" command.
*/

Reparse::Reparse( StringList * args )
    : AoxCommand( args ), d( new ReparseData )
{
}


void Reparse::execute()
{
    if ( !d->q ) {
        parseOptions();
        end();

        printf( "Looking for messages with parse failures\n" );

        database( true );
        AddressCache::setup();
        FieldNameCache::setup();
        Mailbox::setup( this );

        d->q = new Query( "select mm.mailbox,mm.uid,mm.message as wrapper,"
                          "b.id as bodypart,b.text,b.data "
                          "from unparsed_messages u "
                          "join bodyparts b on (u.bodypart=b.id) "
                          "join part_numbers p on (p.bodypart=b.id) "
                          "join mailbox_messages mm on (p.message=mm.message)",
                          this );
        d->q->execute();
    }

    if ( !choresDone() )
        return;

    if ( d->injector ) {
        if ( !d->injector->done() )
            return;

        if ( d->injector->failed() ) {
            error( "Couldn't inject reparsed message: " +
                   d->injector->error() );
        }
        else {
            d->t = new Transaction( this );
            Query * q =
                new Query( "delete from unparsed_messages where "
                           "bodypart=$1", this );
            q->bind( 1, d->row->getInt( "bodypart" ) );
            d->t->enqueue( q );
            q = new Query( "insert into deleted_messages "
                           "(mailbox,uid,message,modseq,deleted_by,reason) "
                           "values ($1,$2,$3,$4,$5,$6)", this );
            q->bind( 1, d->row->getInt( "mailbox" ) );
            q->bind( 2, d->row->getInt( "uid" ) );
            q->bind( 3, d->row->getInt( "wrapper" ) );
            q->bind( 4, d->msg->modSeq( d->m ) );
            q->bindNull( 5 );
            q->bind( 6,
                     String( "reparsed as uid " ) +
                     fn( d->msg->uid( d->m ) ) +
                     " by aox " +
                     Configuration::compiledIn( Configuration::Version ) );
            d->t->enqueue( q );
            d->t->commit();
            printf( "- reparsed %s:%d (new UID %d)\n",
                    d->m->name().utf8().cstr(),
                    d->row->getInt( "uid" ),
                    d->msg->uid( d->m ) );
        }

        d->injector = 0;
    }
    else if ( d->t ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() )
            error( "Couldn't delete reparsed message: " + d->t->error() );

        d->t = 0;
    }

    while ( d->q->hasResults() && !d->injector ) {
        Row * r = d->q->nextRow();

        String text;
        if ( r->isNull( "data" ) )
            text = r->getString( "text" );
        else
            text = r->getString( "data" );
        d->m = Mailbox::find( r->getInt( "mailbox" ) );
        d->msg = new Message( text );
        if ( d->m && d->msg->valid() ) {
            d->row = r;
            d->msg->addMailbox( d->m );
            d->injector = new Injector( d->msg, this );
            d->injector->execute();
        }
        else {
            printf( "- parsing %s:%d still fails: %s\n",
                    d->m->name().utf8().cstr(), r->getInt( "uid" ),
                    d->msg->error().simplified().cstr() );
            if ( opt( 'e' ) )
                printf( "- wrote a copy to %s\n",
                        writeErrorCopy( text ).cstr() );
        }
    }

    if ( !d->q->done() )
        return;
    if ( d->injector && !d->injector->done() )
        return;

    finish();
}


static String * errdir = 0;
static uint uniq = 0;


/*! Writes a copy of \a o to a file and returns its name. Tries to
    write \a o in anonymised form.
*/

String Reparse::writeErrorCopy( const String & o )
{
    Message * m = new Message( o );
    String a = o.anonymised();
    Message * am = new Message( a );
    String dir;
    String name;
    String c;
    if ( !errdir ) {
        errdir = new String;
        Allocator::addEternal( errdir, "error directory" );
        errdir->append( "errors/" );
        errdir->append( fn( getpid() ) );
        ::mkdir( "errors", 0777 );
        ::mkdir( errdir->cstr(), 0777 );
    }
    if ( opt( 'v' ) < 2 &&
         am->error().anonymised() == m->error().anonymised() ) {
        dir = *errdir + "/anonymised";
        name = fn( ++uniq );
        c = a;
    }
    else {
        dir = *errdir + "/plaintext";
        name = fn( ++uniq );
        c = o;
    }
    ::mkdir( dir.cstr(), 0777 );
    String r = dir + "/" + name;
    File f( r, File::Write );
    f.write( c );
    return r;
}
