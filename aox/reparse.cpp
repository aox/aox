// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "reparse.h"

#include "file.h"
#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "injector.h"
#include "integerset.h"
#include "transaction.h"

#include <stdio.h>
#include <sys/stat.h> // mkdir
#include <sys/types.h> // mkdir
#include <unistd.h> // getpid


class ReparseData
    : public Garbage
{
public:
    ReparseData()
        : q( 0 ), t( 0 )
    {}

    Query * q;
    Transaction * t;
};


static AoxFactory<Reparse>
f( "reparse", "", "Retry previously-stored unparsable messages.",
   "    Synopsis: aox reparse\n\n"
   "    Looks for messages that \"arrived but could not be stored\",\n"
   "    and tries to reparse them with parsing workarounds added more\n"
   "    recently. If it succeeds, the new messages are injected.\n" );


/*! \class Reparse reparse.h
    This class handles the "aox reparse" command.
*/

Reparse::Reparse( EStringList * args )
    : AoxCommand( args ), d( new ReparseData )
{
}


void Reparse::execute()
{
    if ( !d->q && !d->t ) {
        parseOptions();
        end();

        printf( "Looking for messages with parse failures\n" );

        database( true );
        Mailbox::setup( this );

        d->t = new Transaction( this );
        d->q = new Query( "select mm.mailbox, mm.uid, mm.modseq, "
                          "mm.message as wrapper, "
                          "mb.nextmodseq, "
                          "b.id as bodypart, b.text, b.data "
                          "from unparsed_messages u "
                          "join bodyparts b on (u.bodypart=b.id) "
                          "join part_numbers p on (p.bodypart=b.id) "
                          "join mailbox_messages mm on (p.message=mm.message) "
                          "join mailboxes mb on (mm.mailbox=mb.id) "
                          "order by mm.mailbox "
                          "for update",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( !choresDone() )
        return;

    if ( !d->q->done() )
        return;

    IntegerSet parsable;

    List<Injectee> injectables;
    while ( d->q && d->q->hasResults() ) {
        Row * r = d->q->nextRow();

        EString text;
        if ( r->isNull( "data" ) )
            text = r->getEString( "text" );
        else
            text = r->getEString( "data" );
        Mailbox * mb = Mailbox::find( r->getInt( "mailbox" ) );
        Injectee * im = new Injectee;
        im->parse( text );
        if ( im->valid() ) {
            EStringList x;
            im->setFlags( mb, &x );
            injectables.append( im );

            parsable.add( r->getInt( "bodypart" ) );

            Query * q
                = new Query( "insert into deleted_messages "
                             "(mailbox,uid,message,modseq,deleted_by,reason) "
                             "values ($1,$2,$3,$4,$5,$6)", this );
            q->bind( 1, r->getInt( "mailbox" ) );
            q->bind( 2, r->getInt( "uid" ) );
            q->bind( 3, r->getInt( "wrapper" ) );
            q->bind( 4, r->getBigint( "nextmodseq" ) );
            q->bindNull( 5 );
            q->bind( 6,
                     EString( "reparsed by aox " ) +
                     Configuration::compiledIn( Configuration::Version ) );
            d->t->enqueue( q );
            printf( "- reparsed %s:%d\n",
                    mb->name().utf8().cstr(),
                    r->getInt( "uid" ) );
        }
        else {
            printf( "- parsing %s:%d still fails: %s\n",
                    mb->name().utf8().cstr(), r->getInt( "uid" ),
                    im->error().simplified().cstr() );
            if ( opt( 'e' ) )
                printf( "- wrote a copy to %s\n",
                        writeErrorCopy( text ).cstr() );
        }

    }
    if ( !injectables.isEmpty() ) {
        Query * q =
            new Query( "delete from unparsed_messages where "
                       "bodypart=any($1)", this );
        q->bind( 1, parsable );
        d->t->enqueue( q );

        Injector * injector = new Injector( this );
        injector->addInjection( &injectables );
        injector->setTransaction( d->t );
        injector->execute();

    }

    d->t->commit();

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Reparsing failed: " + d->t->error() );
    finish();
}


static EString * errdir = 0;
static uint uniq = 0;


/*! Writes a copy of \a o to a file and returns its name. Tries to
    write \a o in anonymised form.
*/

EString Reparse::writeErrorCopy( const EString & o )
{
    Message * m = new Message;
    m->parse( o );
    EString a = o.anonymised();
    Message * am = new Message;
    am->parse( a );
    EString dir;
    EString name;
    EString c;
    if ( !errdir ) {
        errdir = new EString;
        Allocator::addEternal( errdir, "error directory" );
        errdir->append( "errors/" );
        errdir->appendNumber( getpid() );
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
    EString r = dir + "/" + name;
    File f( r, File::Write );
    f.write( c );
    return r;
}
