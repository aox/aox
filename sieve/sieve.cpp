// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieve.h"

#include "md5.h"
#include "utf.h"
#include "date.h"
#include "html.h"
#include "user.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "bodypart.h"
#include "collation.h"
#include "mimefields.h"
#include "stringlist.h"
#include "ustringlist.h"
#include "sievescript.h"
#include "sieveaction.h"
#include "addressfield.h"
#include "configuration.h"
#include "sieveproduction.h"


class SieveData
    : public Garbage
{
public:
    SieveData()
        : sender( 0 ),
          currentRecipient( 0 ),
          message( 0 )
        {}

    class Recipient
        : public Garbage
    {
    public:
        Recipient( Address * a, Mailbox * m, SieveData * data )
            : d( data ), address( a ), mailbox( m ),
              done( false ), ok( true ),
              implicitKeep( true ), explicitKeep( false ),
              sq( 0 ), script( new SieveScript ), user( 0 ), handler( 0 )
        {
            d->recipients.append( this );
        }

        SieveData * d;
        Address * address;
        Mailbox * mailbox;
        bool done;
        bool ok;
        bool implicitKeep;
        bool explicitKeep;
        String result;
        List<SieveAction> actions;
        List<SieveCommand> pending;
        Query * sq;
        SieveScript * script;
        String error;
        UString prefix;
        User * user;
        EventHandler * handler;

        bool evaluate( SieveCommand * );
        enum Result { True, False, Undecidable };
        Result evaluate( SieveTest * );
    };
    Address * sender;
    List<Recipient> recipients;
    Recipient * currentRecipient;
    Message * message;

    Recipient * recipient( Address * a );
};


SieveData::Recipient * SieveData::recipient( Address * a )
{
    List<SieveData::Recipient>::Iterator it( recipients );
    bool same = false;
    String dom = a->domain().lower();
    String lp = a->localpart().lower();
    do {
        if ( it->address->domain().lower() == dom ) {
            if ( it->mailbox ) {
                if ( it->address->localpart().lower() == lp )
                    same = true;
            }
            else {
                if ( it->address->localpart() == a->localpart() )
                    same = true;
            }
        }
        if ( !same )
            ++it;
    } while ( it && !same );
    return it;
}


/*! \class Sieve sieve.h

    The Sieve class interprets the Sieve language, which processes
    incoming messages to determine their fate.

    The class requires fairly specific usage: An object is created,
    the message sender is set using setSender(), the recipients with
    addRecipient() and the message itself with setMessage().

    Once addRecipient() has been called, evaluate() may be, and can
    give results. It's unlikely (but possible) that results may be
    available before setMessage() has been called.
*/


/*! Constructs an empty message Sieve. */

Sieve::Sieve()
    : EventHandler(), d( new SieveData )
{
}


/*! Used only for database chores - selecting the scripts
    mostly. Anything else?
*/

void Sieve::execute()
{
    bool wasReady = ready();
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( i->sq ) {
            Row * r = i->sq->nextRow();
            if ( r || i->sq->done() )
                i->sq = 0;
            if ( r ) {
                if ( !r->isNull( "mailbox" ) )
                    i->mailbox = Mailbox::find( r->getInt( "mailbox" ) );
                if ( !r->isNull( "script" ) ) {
                    i->prefix = r->getUString( "name" ) + "/" +
                                r->getUString( "login" ) + "/";
                    i->user = new User;
                    i->user->setLogin( r->getUString( "login" ) );
                    i->user->setId( r->getInt( "userid" ) );
                    i->script->parse( r->getString( "script" ) );
                    List<SieveCommand>::Iterator 
                        c(i->script->topLevelCommands());
                    while ( c ) {
                        i->pending.append( c );
                        ++c;
                    }
                }
            }
        }
        ++i;
    }
    if ( ready() && !wasReady ) {
        i = d->recipients.first();
        while ( i ) {
            EventHandler * h = i->handler;
            i->handler = 0;
            ++i;
            if ( h )
                h->execute();
        }
    }
}


/*! Records that the envelope sender is \a address. */

void Sieve::setSender( Address * address )
{
    d->sender = address;
}


/*! Records that \a address is one of the recipients for this message,
    and that \a destination is where the mailbox should be stored by
    default. Sieve will use \a script as script. If \a user is
    non-null, Sieve will check that fileinto statement only files mail
    into mailboxes owned by \a user.
*/

void Sieve::addRecipient( Address * address, Mailbox * destination,
                          User * user, SieveScript * script )
{
    SieveData::Recipient * r
        = new SieveData::Recipient( address, destination, d );
    d->currentRecipient = r;
    r->script = script;
    r->user = user;
    List<SieveCommand>::Iterator c( script->topLevelCommands() );
    while ( c ) {
        r->pending.append( c );
        ++c;
    }
}


/*! Looks up \a address in the aliases table, finds the related sieve
    script and other needed information so that delivery to \a address
    can be evaluated. Calls \a user when the information is available.

    If \a address is not a registered alias, Sieve will refuse mail to
    it.
*/

void Sieve::addRecipient( Address * address, EventHandler * user )
{
    SieveData::Recipient * r
        = new SieveData::Recipient( address, 0, d );
    d->currentRecipient = r;

    r->handler = user;

    r->sq = new Query( "select al.mailbox, s.script, m.owner, "
                       "n.name, u.id as userid, u.login "
                       "from aliases al "
                       "join addresses a on (al.address=a.id) "
                       "join mailboxes m on (al.mailbox=m.id) "
                       "left join scripts s on "
                       " (s.owner=m.owner and s.active='t') "
                       "left join users u on (s.owner=u.id) "
                       "left join namespaces n on (u.parentspace=n.id) "
                       "where m.deleted='f' and "
                       "lower(a.localpart)=$1 and lower(a.domain)=$2", this );
    String localpart( address->localpart() );
    if ( Configuration::toggle( Configuration::UseSubaddressing ) ) {
        Configuration::Text t = Configuration::AddressSeparator;
        String sep( Configuration::text( t ) );
        int n = localpart.find( sep );
        if ( n > 0 )
            localpart = localpart.mid( 0, n );
    }
    r->sq->bind( 1, localpart.lower() );
    r->sq->bind( 2, address->domain().lower() );
    r->sq->execute();
    
}


/*! Records that \a message is to be used while sieving. All sieve
    tests that look at e.g. header fields look at \a message, and \a
    message is stored using fileinto/keep and forwarded using
    redirect.
*/

void Sieve::setMessage( Message * message )
{
    d->message = message;
}


/*! Returns a pointer to the address set with setSender(), or a null
    pointer if setSender() has not yet been called.
*/

Address * Sieve::sender() const
{
    return d->sender;
}


/*! Returns a pointer to the recipient currently being sieved, or a
    null pointer if the Sieve engine is not currently working on any
    particular recipient.

    In the future, I think we'll add a way to sieve between MAIL FROM
    and RCPT TO, so recipient() can realistically return 0.
*/

Address * Sieve::recipient() const
{
    if ( !d->currentRecipient )
        return 0;
    return d->currentRecipient->address;
}


/*! Runs any sieve scripts currently available, sees what results can
    be found, and returns when it can't do anything more. If done() is
    true after evaluate(), evaluate() need not be called again.
*/

void Sieve::evaluate()
{
    if ( !ready() )
        return;

    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( !i->done && !i->pending.isEmpty() ) {
            List<SieveCommand>::Iterator c( i->pending );
            while ( c && !i->done && i->evaluate( c ) )
                (void)i->pending.take( c );
        }
        if ( i->pending.isEmpty() )
            i->done = true;
        if ( i->done &&
             ( i->implicitKeep || i->explicitKeep ) ) {
            SieveAction * a = new SieveAction( SieveAction::FileInto );
            a->setMailbox( i->mailbox );
            i->actions.append( a );
        }
        ++i;
    }
}


bool SieveData::Recipient::evaluate( SieveCommand * c )
{
    if ( c->identifier() == "if" ||
         c->identifier() == "elsif" ||
         c->identifier() == "else" ) {
        Result r = True;
        if ( c->identifier() != "else" )
            r = evaluate( c->arguments()->tests()->firstElement() );
        if ( r == Undecidable ) {
            // cannot evaluate this test with the information
            // available. must wait until more data is available.
            return false;
        }
        else if ( r == True ) {
            // if the condition is true, we want to get rid of the
            // following elsif/else commands and insert the subsidiary
            // block in their place.
            List<SieveCommand>::Iterator f( pending );
            if ( f == c )
                ++f;
            while ( f &&
                    ( f->identifier() == "elsif" ||
                      f->identifier() == "else" ) )
                (void)pending.take( f );
            List<SieveCommand>::Iterator s( c->block()->commands() );
            while ( s ) {
                pending.insert( f, s );
                ++s;
            }
        }
        else if ( r == False ) {
            // if the condition is false, we'll just proceed to the
            // next statement. there is nothing to do in this case.
        }
    }
    else if ( c->identifier() == "require" ) {
        // no action needed
    }
    else if ( c->identifier() == "stop" ) {
        done = true;
    }
    else if ( c->identifier() == "reject" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Reject );
        actions.append( a );
    }
    else if ( c->identifier() == "fileinto" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::FileInto );
        UString arg = c->arguments()->takeString( 1 );
        UString n = arg;
        if ( !arg.startsWith( "/" ) )
            n = prefix + arg;
        a->setMailbox( Mailbox::find( n ) );
        if ( !a->mailbox() ||
             ( user && user->id() != a->mailbox()->owner() ) ) {
            if ( !a->mailbox() )
                error = "No such mailbox: " + arg.utf8();
            else
                error = "Mailbox not owned by " +
                        user->login().utf8() + ": " + arg.utf8();
            if ( n != arg )
                error.append( " (" + n.utf8() + ")" );
            a = new SieveAction( SieveAction::Error );
            a->setErrorMessage( error );
            implicitKeep = true;
            done = true;
        }
        actions.append( a );
    }
    else if ( c->identifier() == "redirect" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Redirect );
        UString arg = c->arguments()->takeString( 1 );
        AddressParser ap( arg.utf8() );
        a->setAddress( ap.addresses()->first() );
        actions.append( a );
    }
    else if ( c->identifier() == "keep" ) {
        implicitKeep = false;
        explicitKeep = true;
        // nothing needed
    }
    else if ( c->identifier() == "discard" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Discard );
        actions.append( a );
    }
    else if ( c->identifier() == "vacation" ) {
        // mostly copied from sieveproduction.cpp. when we have two
        // commands using lots of tags, we'll want to design a
        // framework for transporting tag values.

        SieveArgumentList * al = c->arguments();
        
        // :days
        uint days = 7;
        if ( al->findTag( ":days" ) )
            days = al->takeTaggedNumber( ":days" );

        // :subject
        UString subject = al->takeTaggedString( ":subject" );

        // :from
        Address * from = 0;
        if ( al->findTag( ":from" ) ) {
            AddressParser ap( al->takeTaggedString( ":from" ).utf8() );
            from = ap.addresses()->first();
        }
        if ( !from && d->currentRecipient )
            from = d->currentRecipient->address;

        // :addresses
        List<Address> addresses;
        if ( al->findTag( ":addresses" ) ) {
            UStringList * addressArguments
                = al->takeTaggedStringList( ":addresses" );
            UStringList::Iterator i( addressArguments );
            while ( i ) {
                AddressParser ap( i->utf8() );
                addresses.append( ap.addresses()->first() );
                ++i;
            }
        }
        if ( d->currentRecipient )
            addresses.append( d->currentRecipient->address );
        if ( from &&
             ( !d->currentRecipient ||
               from != d->currentRecipient->address ) )
            addresses.append( from );

        // :mime
        bool mime = false;
        if ( al->findTag( ":mime" ) )
            mime = true;

        // find out whether we need to reply
        bool wantToReply = true;
        if ( !from )
            wantToReply = false;

        // look for suspect senders
        if ( d->sender->type() != Address::Normal )
            wantToReply = false;
        else if ( d->sender->localpart().lower().startsWith( "owner-" ) )
            wantToReply = false;
        else if ( d->sender->localpart().lower().endsWith( "-request" ) )
            wantToReply = false;
        
        // look for header fields we don't like
        if ( wantToReply ) {
            List<HeaderField>::Iterator i( d->message->header()->fields() );
            while ( i && wantToReply ) {
                String n = i->name();
                if ( n == "Auto-Submitted" ||
                     n.startsWith( "List-" ) ||
                     n == "Precedence" ||
                     n == "X-Beenthere" ||
                     n == "X-Loop" )
                    wantToReply = false;
                ++i;
            }
        }

        // match my address(es) against those in To/Cc
        if ( wantToReply ) {
            wantToReply = false;
            List<Address> l;
            l.append( d->message->header()->addresses( HeaderField::To ) );
            l.append( d->message->header()->addresses( HeaderField::Cc ) );
            List<Address>::Iterator i( l );
            while ( i && !wantToReply ) {
                String lp = i->localpart().lower();
                String dom = i->domain().lower();
                List<Address>::Iterator me( addresses );
                while ( me && !wantToReply ) {
                    if ( lp == me->localpart().lower() &&
                         dom == me->domain().lower() )
                        wantToReply = true;
                    ++me;
                }
                ++i;
            }
        }

        // :handle
        UString handle = al->takeTaggedString( ":handle" );

        // reason
        UString reason = al->takeString( 1 );
        Message * reply = 0;

        String reptext;
        reptext.append( "From: " );
        reptext.append( from->toString() );
        reptext.append( "\r\n"
                        "To: " );
        reptext.append( d->sender->toString() );
        reptext.append( "\r\n"
                        "Subject: " );
        if ( subject.isEmpty() ) {
            String s = d->message->header()->subject().simplified();
            while ( s.lower().startsWith( "auto:" ) )
                s = s.mid( 5 ).simplified();
            reptext.append( "Auto: " );
            if ( s.isEmpty() )
                reptext.append( "Vacation" );
            else
                reptext.append( s );
        }            
        else {
            reptext.append( subject.utf8() );
        }
        reptext.append( "\r\n"
                        "Date: " );
        Date replyDate;
        if ( d->message->header()->field( HeaderField::Received ) ) {
            String v = d->message->header()->
                       field( HeaderField::Received )->value();
            int i = 0;
            while ( v.find( ';', i+1 ) > 0 )
                i = v.find( ';', i+1 );
            if ( i >= 0 ) {
                Date tmp;
                tmp.setRfc822( v.mid( i+1 ) );
                if ( tmp.valid() )
                    replyDate = tmp;
            }
        }
        else {
            replyDate.setCurrentTime();
        }
        
        reptext.append( replyDate.rfc822() );
        reptext.append( "\r\n"
                        "Auto-Submitted: auto-replied\r\n"
                        "Precedence: junk\r\n" );

        if ( !wantToReply ) {
            // no need to do either
        }
        else if ( mime ) {
            reptext.append( reason.utf8() );
            reply = new Message( reptext, 0 );
        }
        else {
            if ( !reason.isAscii() )
                reptext.append( "Content-Type: text/plain; charset=utf-8\r\n"
                                "Mime-Version: 1.0\r\n" );
            reptext.append( "\r\n" );
            reptext.append( reason.utf8() );
            reply = new Message( reptext, 0 );
        }

        if ( wantToReply && handle.isEmpty() ) {
            handle = subject;
            handle.append( "easter eggs are forever" );
            handle.append( reason );
            MD5 md5;
            AsciiCodec ac;
            handle = ac.toUnicode( md5.hash( handle.utf8() ).e64() );
        }

        if ( wantToReply ) {
            SieveAction * a = new SieveAction( SieveAction::Vacation );
            actions.append( a );
            a->setMessage( reply );
            a->setAddress( d->sender );
            a->setHandle( handle );
        }
    }
    else {
        // ?
    }
    return true;
}


static void addAddress( UStringList * l, Address * a,
                        SieveTest::AddressPart p )
{
    UString * s = new UString;
    Utf8Codec c;

    String user;
    String detail;
    String localpart( a->localpart() );

    if ( Configuration::toggle( Configuration::UseSubaddressing ) ) {
        Configuration::Text p = Configuration::AddressSeparator;
        String sep( Configuration::text( p ) );
        int n = localpart.find( sep );
        if ( n > 0 ) {
            user = localpart.mid( 0, n );
            detail = localpart.mid( n+sep.length() );
        }
    }
    else {
        user = localpart;
    }

    if ( p == SieveTest::User ) {
        s->append( c.toUnicode( user ) );
    }
    else if ( p == SieveTest::Detail ) {
        // XXX: foo@ and foo+@ are supposed to be treated differently
        // here, but we pretend they're the same.
        s->append( c.toUnicode( detail ) );
    }
    else {
        if ( p != SieveTest::Domain )
            s->append( c.toUnicode( localpart ) );
        if ( p == SieveTest::All || p == SieveTest::NoAddressPart )
            s->append( "@" );
        if ( p != SieveTest::Localpart )
            s->append( c.toUnicode( a->domain() ) );
    }

    l->append( s );
}


SieveData::Recipient::Result SieveData::Recipient::evaluate( SieveTest * t )
{
    UStringList * haystack = 0;
    if ( t->identifier() == "address" ) {
        if ( !d->message )
            return Undecidable;
        haystack = new UStringList;
        List<HeaderField>::Iterator hf( d->message->header()->fields() );
        Utf8Codec c;
        while ( hf ) {
            if ( hf->type() <= HeaderField::LastAddressField &&
                 t->headers()->contains( c.toUnicode( hf->name() ) ) ) {
                AddressField * af = (AddressField*)((HeaderField*)hf);
                List<Address>::Iterator a( af->addresses() );
                while ( a ) {
                    addAddress( haystack, a, t->addressPart() );
                    ++a;
                }
            }
            ++hf;
        }
    }
    else if ( t->identifier() == "allof" ) {
        Result r = True;
        List<SieveTest>::Iterator i( t->arguments()->tests() );
        while ( i ) {
            Result ir = evaluate( i );
            if ( ir == False )
                return False;
            else if ( ir == Undecidable )
                r = Undecidable;
            ++i;
        }
        return r;
    }
    else if ( t->identifier() == "anyof" ) {
        Result r = False;
        List<SieveTest>::Iterator i( t->arguments()->tests() );
        while ( i ) {
            Result ir = evaluate( i );
            if ( ir == True )
                return True;
            else if ( ir == Undecidable )
                r = Undecidable;
            ++i;
        }
        return r;
    }
    else if ( t->identifier() == "envelope" ) {
        haystack = new UStringList;
        UStringList::Iterator i( t->envelopeParts() );
        while ( i ) {
            if ( *i == "from" )
                addAddress( haystack, d->sender, t->addressPart() );
            else if ( *i == "to" )
                addAddress( haystack, address, t->addressPart() );
            ++i;
        }
    }
    else if ( t->identifier() == "exists" ||
              t->identifier() == "header" )
    {
        if ( !d->message )
            return Undecidable;
        haystack = new UStringList;
        UStringList::Iterator i( t->headers() );
        Result r = True;
        while ( i ) {
            uint hft = HeaderField::fieldType( i->ascii() );

            if ( ( hft > 0 && hft <= HeaderField::LastAddressField &&
                   !d->message->hasAddresses() ) ||
                 !d->message->hasHeaders() )
                r = Undecidable;

            Utf8Codec c;
            List<HeaderField>::Iterator hf( d->message->header()->fields() );
            while ( hf ) {
                // XXX this is wrong and probably breaks when the
                // header field contains =?iso-8859-1?q?=C0?= and
                // the blah searches for U+00C0.
                if ( hf->name() == i->ascii() )
                    haystack->append( c.toUnicode( hf->value() ) );
                ++hf;
            }

            if ( t->identifier() == "exists" && haystack->isEmpty() )
                return False;

            ++i;
        }
        if ( t->identifier() == "exists" )
            return r;
    }
    else if ( t->identifier() == "date" ||
              t->identifier() == "currentdate" )
    {
        if ( t->identifier() == "date" &&
             !( d->message && d->message->hasHeaders() ) )
            return Undecidable;

        Date dt;
        if ( t->headers() ) {
            UString * hk = t->headers()->first();
            List<HeaderField>::Iterator hf( d->message->header()->fields() );
            while ( hf && hf->name() != hk->ascii() )
                ++hf;
            if ( hf )
                dt.setRfc822( hf->value() );
        }
        else {
            dt.setCurrentTime();
        }

        // XXX: dt.setTimezone( t->timeZone() );

        if ( dt.valid() ) {
            String s;
            String z( "0000" );

            String dp( t->datePart().ascii() );
            if ( dp == "year" ) {
                z.append( fn( dt.year() ) );
                s.append( z.mid( z.length()-4 ) );
            }
            else if ( dp == "month" ) {
                z.append( fn( dt.month() ) );
                s.append( z.mid( z.length()-2 ) );
            }
            else if ( dp == "day" ) {
                z.append( fn( dt.day() ) );
                s.append( z.mid( z.length()-2 ) );
            }
            else if ( dp == "date" ) {
                s.append( dt.isoDate() );
            }
            else if ( dp == "julian" ) {
                s.append( fn( 40587 + dt.unixTime()/86400 ) );
            }
            else if ( dp == "hour" ) {
                z.append( fn( dt.hour() ) );
                s.append( z.mid( z.length()-2 ) );
            }
            else if ( dp == "minute" ) {
                z.append( fn( dt.minute() ) );
                s.append( z.mid( z.length()-2 ) );
            }
            else if ( dp == "second" ) {
                z.append( fn( dt.second() ) );
                s.append( z.mid( z.length()-2 ) );
            }
            else if ( dp == "time" ) {
                s.append( dt.isoTime() );
            }
            else if ( dp == "iso8601" ) {
                s.append( dt.isoDateTime() );
            }
            else if ( dp == "std11" ) {
                s.append( dt.rfc822() );
            }
            else if ( dp == "zone" ) {
                int n = dt.offset();
                if ( n < 0 ) {
                    n = -n;
                    s.append( "-" );
                }
                else {
                    s.append( "+" );
                }
                z.append( fn( n / 60 ) );
                s.append( z.mid( z.length() - 2 ) );
                z = "00";
                z.append( fn( n % 60 ) );
                s.append( z.mid( z.length() - 2 ) );
            }
            else if ( dp == "weekday" ) {
                s.append( fn( dt.weekday() ) );
            }

            UString ds;
            Utf8Codec c;
            ds.append( c.toUnicode( s ) );
            haystack = new UStringList;
            haystack->append( ds );
        }
    }
    else if ( t->identifier() == "false" ) {
        return False;
    }
    else if ( t->identifier() == "not" ) {
        List<SieveTest>::Iterator i( t->arguments()->tests() );
        if ( i ) {
            switch ( evaluate( i ) ) {
            case True:
                return False;
                break;
            case False:
                return True;
                break;
            case Undecidable:
                return Undecidable;
                break;
            }
        }
        return False; // should never happen
    }
    else if ( t->identifier() == "size" ) {
        if ( !d->message )
            return Undecidable;
        if ( t->sizeOverLimit() ) {
            if ( d->message->rfc822Size() > t->sizeLimit() )
                return True;
        }
        else {
            if ( d->message->rfc822Size() < t->sizeLimit() )
                return True;
        }
        return False;
    }
    else if ( t->identifier() == "true" ) {
        return True;
    }
    else if ( t->identifier() == "body" ) {
        if ( !d->message ) {
            return Undecidable;
        }
        else if ( t->bodyMatchType() == SieveTest::Rfc822 ) {
            haystack = new UStringList;
            AsciiCodec a;
            haystack->append( a.toUnicode( d->message->body() ) );
        }
        else {
            haystack = new UStringList;
            List<Bodypart>::Iterator i( d->message->allBodyparts() );
            while ( i ) {
                Header * h = i->header();
                String ct;
                if ( !h->contentType() ) {
                    switch( h->defaultType() ) {
                    case Header::TextPlain:
                        ct = "text/plain";
                        break;
                    case Header::MessageRfc822:
                        ct = "message/rfc822";
                        break;
                    }
                }
                else {
                    ct = h->contentType()->type() + "/" +
                         h->contentType()->subtype();
                }

                bool include = false;
                if ( t->bodyMatchType() == SieveTest::Text ) {
                    if ( ct.startsWith( "text/" ) )
                        include = true;
                }
                else {
                    UStringList::Iterator k( t->contentTypes() );
                    while ( k ) {
                        String mk = k->ascii();
                        ++k;
                        // this logic is based exactly on the draft.
                        if ( mk.startsWith( "/" ) ||
                             mk.endsWith( "/" ) ||
                             ( mk.find( '/' ) >= 0 &&
                               mk.find( mk.find( '/' ) + 1 ) >= 0 ) ) {
                            // matches no types
                        }
                        else if ( mk.contains( '/' ) ) {
                            // matches ->type()/->subtype()
                            if ( ct == mk.lower() )
                                include = true;
                        }
                        else if ( mk.isEmpty() ) {
                            // matches all types
                            include = true;
                        }
                        else {
                            // matches ->type();
                            if ( ct.startsWith( mk.lower() + "/" ) )
                                include = true;
                        }
                    }
                }
                if ( include ) {
                    AsciiCodec a;
                    if ( ct == "text/html" )
                        haystack->append( HTML::asText( i->text() ) );
                    else if ( ct.startsWith( "multipart/" ) )
                        // draft says to search prologue+epilogue
                        haystack->append( new UString );
                    else if ( ct == "message/rfc822" )
                        haystack->append(a.toUnicode(i->message()
                                                     ->header()->asText()));
                    else if ( ct.startsWith( "text/" ) )
                        haystack->append( i->text() );
                    else
                        haystack->append( a.toUnicode( i->data() ) );
                }
                ++i;
            }
        }
    }
    else {
        // unknown test. wtf?
        return False;
    }

    Collation * c = t->comparator();
    if ( !c )
        c = Collation::create( us( "i;ascii-casemap" ) );

    if ( t->matchType() == SieveTest::Count ) {
        UString * hn = new UString;
        hn->append( fn( haystack->count() ).cstr() );
        haystack->clear();
        haystack->append( hn );
    }

    UStringList::Iterator h( haystack );
    while ( h ) {
        UString s( *h );

        UStringList::Iterator k( t->keys() );
        while ( k ) {
            UString g( *k );

            switch ( t->matchType() ) {
            case SieveTest::Is:
                if ( c->equals( s, g ) )
                    return True;
                break;
            case SieveTest::Contains:
                if ( c->contains( s, g ) )
                    return True;
                break;
            case SieveTest::Matches:
                if ( Mailbox::match( g, 0, s, 0 ) == 2 )
                    return True;
                break;
            case SieveTest::Count:
            case SieveTest::Value:
                int n = c->compare( s, g );
                switch ( t->matchOperator() ) {
                case SieveTest::GT:
                    if ( n > 0 )
                        return True;
                    break;
                case SieveTest::GE:
                    if ( n >= 0 )
                        return True;
                    break;
                case SieveTest::LT:
                    if ( n < 0 )
                        return True;
                    break;
                case SieveTest::LE:
                    if ( n <= 0 )
                        return True;
                    break;
                case SieveTest::EQ:
                    if ( n == 0 )
                        return True;
                    break;
                case SieveTest::NE:
                    if ( n != 0 )
                        return True;
                    break;
                case SieveTest::None:
                    break;
                }
                break;
            }
            ++k;
        }
        ++h;
    }

    return False;
}




/*! Returns true if delivery to \a address succeeded, and false if it
    failed or if evaluation is not yet complete.
*/

bool Sieve::succeeded( Address * address ) const
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && i->ok;
    return false;
}


/*! Returns true if \a address is known to be a local address, and
    false if \a address is not known(), if the Sieve isn't ready() or if
    \a address is remote.
  
    If the Sieve is ready() and \a address is not local(), then it
    must be a remote address.
*/

bool Sieve::local( Address * address ) const
{
    if ( !ready() )
        return false;
    SieveData::Recipient * i = d->recipient( address );
    if ( i && i->mailbox )
        return true;
    return false;
}


/*! Returns true if delivery to \a address failed or will fail, and
    false if it succeeded or if evaluation is not yet complete.
*/

bool Sieve::failed( Address * address ) const
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && !i->ok;
    return false;
}


/*! Returns true if delivery to \a address should be rejected, and
    false if it should be accepted, if evaluation is not yet complete
    or if \a address is not managed by this sieve.
*/

bool Sieve::rejected( Address * address ) const
{
    SieveData::Recipient * i = d->recipient( address );
    if ( !i )
        return false;

    List<SieveAction>::Iterator a( i->actions );
    while ( a ) {
        if ( a->type() == SieveAction::Reject )
            return true;
        ++a;
    }
    return false;
}


/*! Returns an error message if delivery to \a address caused a
    run-time error, and an empty string if all is in order or \a
    address is not a valid address.
*/

String Sieve::error( Address * address ) const
{
    SieveData::Recipient * i = d->recipient( address );
    if ( !i )
        return "";
    return i->error;
}


/*! Returns an error message if delivery to any address caused a
    run-time error, and an empty string in all other cases.
*/

String Sieve::error() const
{
    List<SieveData::Recipient>::Iterator it( d->recipients );
    while ( it && it->error.isEmpty() )
        ++it;
    if ( it )
        return it->error;
    return "";
}


/*! Returns true if the Sieve has finished evaluation (although not
    execution), and false if there's more to do before evaluation is
    complete.
*/

bool Sieve::done() const
{
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( !i->done )
            return false;
        ++i;
    }
    return true;
}


/*! Records that \a action is to be performed if evaluation of the
    current user's sieve script does not fail.

    At some point, this may/will also do something of a more general
    nature if there is no current recipient. Global sieve scripts,
    etc.
*/

void Sieve::addAction( SieveAction * action )
{
    if ( d->currentRecipient )
        d->currentRecipient->actions.append( action );
}


/*! Returns a list of all actions this Sieve has decided that \a
    address need performed. It returns a null pointer if \a address
    has never been passed to addRecipient(), and a pointer to a
    (possibly empty) list if \a address has been added.
*/

List<SieveAction> * Sieve::actions( const Address * address ) const
{
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i && i->address != address )
        ++i;
    if ( !i )
        return 0;
    return &i->actions;
}


/*! Returns a list of the Mailbox objects to which the message should
    be delivered. This won't quite do when we implement the imapflags
    extension - then, the different mailboxes mailboxes may need
    different flags.

    The return value is never 0.
*/

List<Mailbox> * Sieve::mailboxes() const
{
    List<Mailbox> * r = new List<Mailbox>;
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        List<SieveAction>::Iterator a( i->actions );
        while ( a ) {
            if ( a->type() == SieveAction::FileInto &&
                 !r->find( a->mailbox() ) )
                r->append( a->mailbox() );
            ++a;
        }
        ++i;
    }
    return r;
}


/*! Returns a list of the Address objects to which this message should
    be forwarded. According to RFC 3028 the envelope sender should not
    be changed.

    The return value is never 0.
*/

List<Address> * Sieve::forwarded() const
{
    List<Address> * r = new List<Address>;
    StringList uniq;
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        List<SieveAction>::Iterator a( i->actions );
        while ( a ) {
            if ( a->type() == SieveAction::Redirect ) {
                String s = a->address()->localpart() + "@" +
                           a->address()->domain();
                if ( !uniq.contains( s ) ) {
                    uniq.append( s );
                    r->append( a->address() );
                }
            }
            ++a;
        }
        ++i;
    }
    return r;
}


/*! Returns true if this message has been rejected by (all of its)
    recipient(s), and false if it's been accepted by at least one.
*/

bool Sieve::rejected() const
{
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        bool r = false;
        List<SieveAction>::Iterator a( i->actions );
        while ( a ) {
            if ( a->type() == SieveAction::Reject )
                r = true;
            ++a;
        }
        ++i;
        if ( !r )
            return false;
    }
    return true;
}


/*! Returns true if evaluate() may be called, and false if execute()
    still has work to do.
*/

bool Sieve::ready() const
{
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i && !i->sq )
        ++i;
    if ( i )
        return false;
    return true;
}


/*! Records that when evaluating mailbox names in the context of \a
    address, a mailbox name which does not start with '/' is relative
    to \a prefix.

    \a prefix must end with '/'. Does nothing unless \a address is a
    known recipient for this sieve.
*/

void Sieve::setPrefix( Address * address, const UString & prefix )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        i->prefix = prefix;
}
