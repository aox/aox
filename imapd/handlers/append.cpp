// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "append.h"

#include "user.h"
#include "date.h"
#include "query.h"
#include "fetcher.h"
#include "mailbox.h"
#include "injector.h"
#include "annotation.h"
#include "imapsession.h"
#include "recipient.h"
#include "imapurl.h"
#include "section.h"
#include "message.h"
#include "string.h"
#include "fetch.h"
#include "imap.h"
#include "list.h"


struct Textpart
    : public Garbage
{
    Textpart()
        : type( Text ), url( 0 ), mailbox( 0 ), message( 0 ),
          section( 0 ), hf( 0 ), bf( 0 )
    {}

    enum Type { Text, Url };

    Type type;
    String s;
    ImapUrl * url;
    Mailbox * mailbox;
    Message * message;
    Section * section;

    MessageHeaderFetcher * hf;
    MessageBodyFetcher * bf;
};


class AppendData
    : public Garbage
{
public:
    AppendData()
        : mailbox( 0 ), message( 0 ), injector( 0 ),
          annotations( 0 ), textparts( 0 ),
          createdFetchers( false )
    {}

    Date date;
    String mbx;
    Mailbox * mailbox;
    Message * message;
    Injector * injector;
    StringList flags;
    List<Annotation> * annotations;
    List<Textpart> * textparts;
    String text;
    bool createdFetchers;
};


/*! \class Append append.h
    Adds a message to a mailbox (RFC 3501 section 6.3.11)

    Parsing mostly relies on the Message class, execution on the
    Injector. There is no way to insert anything but conformant
    messages, unlike some other IMAP servers. How could we do that?
    Not at all, I think.
*/

Append::Append()
    : Command(), d( new AppendData )
{
    // nothing more needed
}


void Append::parse()
{
    // the grammar used is:
    // append = "APPEND" SP mailbox SP [flag-list SP] [date-time SP] literal
    space();
    d->mbx = astring();
    space();

    if ( present( "(" ) ) {
        if ( nextChar() != ')' ) {
            d->flags.append( flag() );
            while( nextChar() == ' ' ) {
                space();
                d->flags.append( flag() );
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
        String month = letters( 3, 3 );
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
        d->date.setDate( year, month, day, hour, minute, second, zone );
        if ( !d->date.valid() )
            error( Bad, "Date supplied is not valid" );
    }

    if ( present( "ANNOTATION " ) ) {
        d->annotations = new List<Annotation>;
        require( "(" );

        bool entriesDone = false;

        do {
            String entry( astring() );
            if ( entry.startsWith( "/flags/" ) || entry.contains( "//" ) ||
                 entry.contains( "*" ) || entry.contains( "%" ) ||
                 entry.endsWith( "/" ) )
            {
                error( Bad, "Invalid annotation entry name: " + entry );
                return;
            }

            AnnotationName * n = AnnotationName::find( entry );
            if ( !n )
                n = new AnnotationName( entry );

            space();
            require( "(" );
            bool attribsDone = false;
            do {
                int oid;

                String attrib( astring() );
                if ( attrib.lower() == "value.priv" ) {
                    oid = imap()->user()->id();
                }
                else if ( attrib.lower() == "value.shared" ) {
                    oid = 0;
                }
                else {
                    error( Bad, "Invalid annotation attribute: " + attrib );
                    return;
                }

                space();

                if ( present( "nil" ) ) {
                    // We don't need to store this at all.
                }
                else {
                    Annotation * a = new Annotation;
                    a->setEntryName( n );
                    a->setOwnerId( oid );
                    a->setValue( string() );
                    d->annotations->append( a );
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

    if ( present( "CATENATE " ) ) {
        d->textparts = new List<Textpart>;
        require( "(" );

        bool done = false;

        do {
            Textpart * tp = new Textpart;
            if ( present( "URL " ) ) {
                tp->type = Textpart::Url;
                tp->s = astring();
            }
            else if ( present( "TEXT " ) ) {
                tp->type = Textpart::Text;
                tp->s = literal();
            }
            else {
                error( Bad, "Expected cat-part, got: " + following() );
            }
            d->textparts->append( tp );

            if ( nextChar() == ' ' )
                space();
            else
                done = true;
        }
        while ( !done );

        require( ")" );
    }
    else {
        d->text = literal();
    }

    end();
}


/*! This new version of number() demands \a n digits and returns the
    number.
*/

uint Append::number( uint n )
{
    String tmp = digits( n, n );
    return tmp.number( 0 );
}


void Append::execute()
{
    if ( !d->mailbox ) {
        d->mailbox = mailbox( d->mbx );
        if ( !d->mailbox ) {
            error( No, "No such mailbox: '" + d->mbx + "'" );
            return;
        }
        requireRight( d->mailbox, Permissions::Insert );
        requireRight( d->mailbox, Permissions::Write );

        List<Textpart>::Iterator it( d->textparts );
        while ( it ) {
            Textpart * tp = it;
            if ( tp->type == Textpart::Url ) {
                ImapUrl * u = new ImapUrl( imap(), tp->s );
                if ( !u->valid() ) {
                    error( No, "[BADURL " + tp->s + "] invalid URL" );
                    return;
                }

                Mailbox * m = mailbox( u->mailbox() );
                if ( !m ) {
                    error( No, "[BADURL " + tp->s + "] invalid mailbox" );
                    return;
                }

                requireRight( m, Permissions::Read );
                tp->mailbox = m;
                tp->url = u;
            }
            ++it;
        }
    }

    if ( !permitted() )
        return;

    if ( !d->createdFetchers ) {
        List<Textpart>::Iterator it( d->textparts );
        while ( it ) {
            Textpart * tp = it;
            if ( tp->type == Textpart::Url ) {
                String section( tp->url->section() );
                if ( !section.isEmpty() )
                    tp->section = Fetch::parseSection( section );

                // XXX: Need to do UID translation for views here.
                MessageSet s;
                uint uid = tp->url->uid();
                s.add( uid, uid );

                if ( !tp->section || tp->section->needsHeader ) {
                    tp->hf = new MessageHeaderFetcher( tp->mailbox );
                    tp->hf->insert( s, this );
                }

                if ( !tp->section || tp->section->needsBody ) {
                    tp->bf = new MessageBodyFetcher( tp->mailbox );
                    tp->bf->insert( s, this );
                }
            }
            ++it;
        }
        d->createdFetchers = true;
    }

    if ( !d->message ) {
        List<Textpart>::Iterator it( d->textparts );
        while ( it ) {
            Textpart * tp = it;
            if ( tp->type == Textpart::Text ) {
                d->text.append( tp->s );
            }
            else {
                if ( ( tp->hf && !tp->hf->done() ) ||
                     ( tp->bf && !tp->bf->done() ) )
                    break;

                Message * m =
                    tp->mailbox->message( tp->url->uid(), false );

                if ( !m ) {
                    error( No, "[BADURL " + tp->s + "] invalid UID" );
                    return;
                }
                else if ( tp->section ) {
                    d->text.append( Fetch::sectionData( tp->section,
                                                        tp->message ) );
                }
                else {
                    d->text.append( m->rfc822() );
                }
            }
            d->textparts->take( it );
        }

        if ( it )
            return;

        d->message = new Message( d->text );
        d->message->setInternalDate( d->date.unixTime() );
        if ( !d->message->valid() ) {
            error( Bad, d->message->error() );
            return;
        }
    }

    if ( !d->injector ) {
        d->injector = new Injector( d->message, this );
        d->injector->setMailbox( d->mailbox );
        d->injector->setFlags( d->flags );
        d->injector->setAnnotations( d->annotations );
        d->injector->execute();
    }

    if ( imap()->session() && !imap()->session()->initialised() ) {
        imap()->session()->refresh( this );
        return;
    }

    if ( d->injector->failed() )
        error( No, "Could not append to " + d->mbx );

    if ( !d->injector->done() || d->injector->failed() )
        return;

    d->injector->announce();
    setRespTextCode( "APPENDUID " +
                     fn( d->mailbox->uidvalidity() ) +
                     " " +
                     fn( d->injector->uid( d->mailbox ) ) );

    finish();
}
