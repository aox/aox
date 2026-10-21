// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "append.h"

#include "user.h"
#include "date.h"
#include "query.h"
#include "fetcher.h"
#include "mailbox.h"
#include "injector.h"
#include "annotation.h"
#include "imapsession.h"
#include "imapparser.h"
#include "recipient.h"
#include "section.h"
#include "message.h"
#include "estring.h"
#include "fetch.h"
#include "imap.h"
#include "list.h"
#include "flag.h"


struct Appendage
    : public Garbage
{
    Appendage()
        : Garbage(),
          message( 0 ),
          annotations( 0 )
    {}
    Injectee * message;
    EString text;
    EStringList flags;
    List<Annotation> * annotations;
    Date date;
};


class AppendData
    : public Garbage
{
public:
    AppendData()
        : mailbox( 0 ), injector( 0 )
    {}

    Mailbox * mailbox;
    List<Appendage> messages;
    Injector * injector;
};


/*! \class Append append.h
    Adds a message to a mailbox (RFC 3501 section 6.3.11)

    Parsing mostly relies on the Message class, execution on the
    Injector. There is no way to insert anything but conformant
    messages, unlike some other IMAP servers. How could we do that?
    Not at all, I think.

    RFC 3501 gives a basic syntax for Append. RFC 3502 modifies
    it. RFC 4466 modifies it too. RFC 5257 extends the modification
    given by RFC 4466.

    We now use the syntax given by RFC 4466.
*/

Append::Append()
    : Command(), d( new AppendData )
{
    // nothing more needed
}


void Append::parse()
{
    // the grammar used is:

    // append          = "APPEND" SP mailbox 1*append-message
    // append-message  = append-opts SP append-data
    // append-ext      = append-ext-name SP append-ext-value
    // append-ext-name = tagged-ext-label
    // append-ext-value= tagged-ext-val
    // append-data     = literal / literal8 / append-data-ext /
    //                   "UTF8" SP "(" literal8 ")"
    // append-data-ext = tagged-ext / att-annotate
    // append-opts     = [SP flag-list] [SP date-time] *(SP append-ext)

    // att-annotate    = "ANNOTATION" SP
    //                   "(" entry-att *(SP entry-att) ")"

    space();
    d->mailbox = mailbox();

    while ( ok() && !parser()->atEnd() ) {
        space();

        Appendage * h = new Appendage;
        d->messages.append( h );

        if ( present( "(" ) ) {
            if ( nextChar() != ')' ) {
                h->flags.append( flag() );
                while( nextChar() == ' ' ) {
                    space();
                    h->flags.append( flag() );
                }
            }
            require( ")" );
            space();
        }

        if ( present( "\"" ) ) {
            uint day;
            if ( nextChar() == ' ' ) {
                space();
                day = number( 1 );
            }
            else {
                day = number( 2 );
            }
            require( "-" );
            EString month = letters( 3, 3 );
            require( "-" );
            uint year = number( 4 );
            space();
            uint hour = number( 2 );
            require( ":" );
            uint minute = number( 2 );
            require( ":" );
            uint second = number( 2 );
            space();
            int zone = 1;
            if ( nextChar() == '-' )
                zone = -1;
            else if ( nextChar() != '+' )
                error( Bad, "Time zone must start with + or -" );
            step();
            zone = zone * ( ( 60 * number( 2 ) ) + number( 2 ) );
            require( "\"" );
            space();
            h->date.setDate( year, month, day, hour, minute, second, zone );
            if ( !h->date.valid() )
                error( Bad, "Date supplied is not valid" );
        }

        if ( present( "ANNOTATION " ) ) {
            h->annotations = new List<Annotation>;
            require( "(" );

            bool entriesDone = false;

            do {
                EString entry( astring() );
                if ( entry.startsWith( "/flags/" ) || entry.contains( "//" ) ||
                     entry.contains( "*" ) || entry.contains( "%" ) ||
                     entry.endsWith( "/" ) )
                {
                    error( Bad, "Invalid annotation entry name: " + entry );
                    return;
                }

                space();
                require( "(" );
                bool attribsDone = false;
                do {
                    int oid;

                    EString attrib( astring() );
                    if ( attrib.lower() == "value.priv" ) {
                        oid = imap()->user()->id();
                    }
                    else if ( attrib.lower() == "value.shared" ) {
                        oid = 0;
                    }
                    else {
                        error( Bad,
                               "Invalid annotation attribute: " + attrib );
                        return;
                    }

                    space();

                    if ( present( "nil" ) ) {
                        // We don't need to store this at all.
                    }
                    else {
                        Annotation * a = new Annotation;
                        a->setEntryName( entry );
                        a->setOwnerId( oid );
                        a->setValue( string() );
                        h->annotations->append( a );
                    }

                    if ( nextChar() == ' ' )
                        space();
                    else
                        attribsDone = true;
                }
                while ( !attribsDone );
                require( ")" );
                if ( nextChar() == ' ' )
                    space();
                else
                    entriesDone = true;
            }
            while ( !entriesDone );

            require( ")" );
            space();
        }

        if ( present( "UTF8 " ) ) {
            require( "(" );
            h->text = literal();
            require( ")" );
        }
        else {
            h->text = literal();
        }
    }

    end();

    if ( !ok() )
        return;

    requireRight( d->mailbox, Permissions::Insert );
    requireRight( d->mailbox, Permissions::Write );
}


/*! This new version of number() demands \a n digits and returns the
    number.
*/

uint Append::number( uint n )
{
    EString tmp = digits( n, n );
    return tmp.number( 0 );
}


void Append::execute()
{
    if ( !permitted() || !ok() || state() != Executing )
        return;

    List<Appendage>::Iterator h( d->messages );
    bool allDone = true;
    while ( h && ok() ) {
        if ( !h->message )
            process( h );
        if ( !h->message )
            allDone = false;
        ++h;
    }

    if ( !allDone )
        return;

    if ( !d->injector ) {
        List<Injectee> * m = new List<Injectee>;
        h = d->messages.first();
        while ( h ) {
            m->append( h->message );
            ++h;
        }

        d->injector = new Injector( this );
        d->injector->addInjection( m );
        d->injector->execute();
    }

    if ( !d->injector->done() )
        return;

    if ( d->injector->failed() ) {
        error( No, "Could not append to " + d->mailbox->name().ascii() );
        return;
    }

    IntegerSet uids;
    h = d->messages.first();
    while ( h ) {
        uids.add( h->message->uid( d->mailbox ) );
        ++h;
    }
    setRespTextCode( "APPENDUID"
                     " " + fn( d->mailbox->uidvalidity() ) +
                     " " + uids.set() );
    finish();
}


/*! This private execute() helper processes the single message \a h. It
    can be executed in parallel.
*/

void Append::process( class Appendage * h )
{
    if ( h->message )
        return;

    h->message = new Injectee;
    h->message->setInternalDate( h->date.unixTime() );
    h->message->parse( h->text );
    h->message->setFlags( d->mailbox, &h->flags );
    h->message->setAnnotations( d->mailbox, h->annotations );
    if ( !h->message->valid() ) {
        setRespTextCode( "PARSE" );
        error( Bad, h->message->error() );
        return;
    }
}
