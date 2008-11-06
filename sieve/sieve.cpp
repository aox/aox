// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieve.h"

#include "md5.h"
#include "utf.h"
#include "date.h"
#include "html.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "bodypart.h"
#include "injector.h"
#include "collation.h"
#include "mimefields.h"
#include "stringlist.h"
#include "ustringlist.h"
#include "sievescript.h"
#include "sieveaction.h"
#include "spoolmanager.h"
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
          message( 0 ),
          state( 0 ),
          handler( 0 ),
          autoresponses( 0 ),
          injector( 0 )
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
    List<Address> submissions;
    Injectee * message;
    Date * arrivalTime;
    uint state;
    EventHandler * handler;
    Query * autoresponses;
    Injector * injector;

    Recipient * recipient( Address * a );
};


SieveData::Recipient * SieveData::recipient( Address * a )
{
    List<SieveData::Recipient>::Iterator it( recipients );
    bool same = false;
    String dom = a->domain().lower();
    String lp = a->localpart().lower();
    while ( it && !same ) {
        if ( it->address->domain().lower() == dom ) {
            if ( it->mailbox ) {
                // local addresses are case-insensitive
                if ( it->address->localpart().lower() == lp )
                    same = true;
            }
            else {
                // others probably aren't
                if ( it->address->localpart() == a->localpart() )
                    same = true;
            }
        }
        if ( !same )
            ++it;
    }
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

    Sieve extensions are implemented in SieveProduction and Sieve. The
    list is in SieveProduction::supportedExtensions();
*/


/*! Constructs an empty message Sieve. */

Sieve::Sieve()
    : EventHandler(), d( new SieveData )
{
    setLog( new Log( Log::Server ) );
}


/*! Used only for database chores - selecting the scripts
    mostly. Anything else?
*/

void Sieve::execute()
{
    Scope x( log() );

    // 0: find the data needed for evaluate().
    if ( d->state == 0 ) {
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
                        i->prefix = r->getUString( "namespace" ) + "/" +
                                    r->getUString( "login" ) + "/";
                        i->user = new User;
                        i->user->setLogin( r->getUString( "login" ) );
                        i->user->setId( r->getInt( "userid" ) );
                        i->user->setAddress( new Address(
                                                 r->getUString( "name" ),
                                                 r->getString( "localpart" ),
                                                 r->getString( "domain" ) ) );
                        i->script->parse( r->getString( "script" ).crlf() );
                        String errors = i->script->parseErrors();
                        if ( !errors.isEmpty() ) {
                            log( "Note: Sieve script for " +
                                 i->user->login().utf8() +
                                 "had parse errors.", Log::Error );
                            String prefix = "Sieve script for " +
                                            i->user->login().utf8();
                            StringList::Iterator i(
                                StringList::split( '\n', errors ) );
                            while ( i ) {
                                log( "Sieve: " + *i, Log::Error );
                                ++i;
                            }
                        }
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
        // we do NOT set the state to 1. act() does that.
    }


    // 1: If there are any autoresponses, see whether they ought to be
    // suppressed.
    if ( d->state == 1 ) {
        if ( !d->injector ) {
            d->injector = new Injector( this );
            d->injector->setLog( new Log( Log::Database ) ); // XXX why here?
        }

        if ( d->autoresponses && !d->autoresponses->done() )
            return;

        if ( !d->autoresponses ) {
            List<SieveAction> * v = vacations();
            if ( v->isEmpty() ) {
                d->state = 2;
            }
            else {
                d->autoresponses = new Query( "", this );
                String s = "select handle from autoresponses "
                           "where expires_at > current_timestamp "
                           "and (";
                bool first = true;
                bool n = 1;
                List<SieveAction>::Iterator i( v );
                while ( i ) {
                    if ( !first )
                        s.append( " or " );
                    s.append( "(handle=$" );
                    s.append( fn( n ) );
                    d->autoresponses->bind( n, i->handle() );
                    s.append( " and sent_from in "
                              "(select id from addresses "
                              " where lower(localpart)=$" );
                    s.append( fn( n+1 ) );
                    s.append( " and lower(domain)=$" );
                    s.append( fn( n+2 ) );
                    Address * f = i->senderAddress();
                    d->autoresponses->bind( n+1, f->localpart().lower() );
                    d->autoresponses->bind( n+2, f->domain() );
                    s.append( ") and sent_to in "
                              "(select id from addresses "
                              " where lower(localpart)=$" );
                    s.append( fn( n+3 ) );
                    s.append( " and lower(domain)=$" );
                    s.append( fn( n+4 ) );
                    Address * r = i->recipientAddress();
                    d->autoresponses->bind( n+3, r->localpart().lower() );
                    d->autoresponses->bind( n+4, r->domain().lower() );
                    s.append( "))" );
                    ++i;
                    n += 5;
                    first = false;
                }
                s.append( ")" );
                d->autoresponses->setString( s );
                d->autoresponses->execute();
            }
        }

        if ( d->autoresponses && d->autoresponses->hasResults() ) {
            List<SieveAction> * v = vacations();
            while ( d->autoresponses->hasResults() ) {
                Row * r = d->autoresponses->nextRow();
                UString h = r->getUString( "handle" );
                List<SieveAction>::Iterator i( v );
                while ( i && i->handle() != h )
                    i++;
                if ( i ) {
                    log( "Suppressing vacation response to " +
                         i->recipientAddress()->toString() );
                    v->take( i );
                }
                else {
                    Query * q
                        = new Query(
                            "insert into autoresponses "
                            "(sent_from, sent_to, expires_at, handle) "
                            "values ("
                            "(select id from addresses "
                            " where lower(localpart)=$1 and lower(domain)=$2 "
                            " limit 1), "
                            "(select id from addresses "
                            " where lower(localpart)=$3 and lower(domain)=$4 "
                            " limit 1), "
                            "$5, $6)", 0 );
                    q->bind( 1, i->senderAddress()->localpart().lower() );
                    q->bind( 2, i->senderAddress()->domain().lower() );
                    q->bind( 3, i->recipientAddress()->localpart().lower() );
                    q->bind( 4, i->recipientAddress()->domain().lower() );
                    Date e;
                    e.setCurrentTime();
                    e.setUnixTime( e.unixTime() + 86400 * i->expiry() );
                    q->bind( 5, e.isoDateTime() );
                    q->bind( 6, i->handle() );
                    q->execute();

                    List<Address> * remote = new List<Address>;
                    remote->append( i->recipientAddress() );
                    d->injector->addDelivery( i->message(),
                                              new Address( "", "", "" ),
                                              remote );
                }
            }
            if ( d->autoresponses->done() )
                d->state = 2;
        }
    }


    // 2: main injection of the incoming message
    if ( d->state == 2 ) {
        List<Mailbox>::Iterator i( mailboxes() );
        StringList flags;
        while ( i ) {
            d->message->setFlags( i, &flags );
            ++i;
        }

        if ( !d->message->mailboxes()->isEmpty() ) {
            List<Injectee> x;
            x.append( d->message );
            d->injector->addInjection( &x );
        }

        List<Address> * f = forwarded();
        if ( !f->isEmpty() )
            d->injector->addDelivery( d->message, sender(), f );

        d->state = 3;
        d->injector->execute();
    }

    // 3: wait for the main injector to finish.
    if ( d->state == 3 ) {
        if ( d->injector && !d->injector->done() )
            return;
        if ( d->injector->failed() ) {
            List<SieveData::Recipient>::Iterator i( d->recipients );
            while ( i ) {
                if ( i->error.isEmpty() )
                    i->error = "Injector: " + d->injector->error();
                ++i;
            }
        }
        d->state = 4;
        if ( d->handler )
            d->handler->execute();
    }
}


/*! Records that the envelope sender is \a address. */

void Sieve::setSender( Address * address )
{
    d->sender = address;
}


/*! Records that the message should be forwarded via the smarthost to
    \a address.
*/

void Sieve::addSubmission( Address * address )
{
    d->submissions.append( address );
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
    Scope x( log() );

    SieveData::Recipient * r
        = new SieveData::Recipient( address, 0, d );
    d->currentRecipient = r;

    r->handler = user;

    r->sq = new Query( "select al.mailbox, s.script, m.owner, "
                       "n.name as namespace, u.id as userid, u.login, "
                       "a.name, a.localpart, a.domain "
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


/*! Records that \a message is to be used while sieving, and \a when
    we received it. All sieve tests that look at e.g. header fields
    look at \a message, and \a message is stored using fileinto/keep
    and forwarded using redirect. \a when is only used to record the
    message's arrival time by fileinto/keep.
*/

void Sieve::setMessage( Injectee * message, Date * when )
{
    d->message = message;
    d->arrivalTime = when;
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

    Scope x( log() );

    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( !i->done && !i->pending.isEmpty() ) {
            List<SieveCommand>::Iterator c( i->pending );
            while ( c && !i->done && i->evaluate( c ) )
                (void)i->pending.take( c );
        }
        if ( i->pending.isEmpty() && !i->done ) {
            i->done = true;
            log( "Evaluated Sieve script for " + i->address->toString() );
            List<SieveAction>::Iterator a( i->actions );
            while ( a ) {
                String r;
                switch ( a->type() ) {
                case SieveAction::Reject:
                    r = "reject";
                    break;
                case SieveAction::FileInto:
                    r = "fileinto, mailbox ";
                    r.append( a->mailbox()->name().utf8() );
                    break;
                case SieveAction::Redirect:
                    r = "redirect, to ";
                    r.append( a->recipientAddress()->toString() );
                    break;
                case SieveAction::Discard:
                    r = "discard";
                    break;
                case SieveAction::Vacation:
                    r = "vacation, from ";
                    r.append( a->senderAddress()->toString() );
                    r.append( ", to " );
                    r.append( a->recipientAddress()->toString() );
                    break;
                case SieveAction::Error:
                    r = "error";
                    break;
                }
                log( "Action: " + r );
                ++a;
            }
            if ( i->mailbox && ( i->implicitKeep || i->explicitKeep ) ) {
                i->implicitKeep = false;
                SieveAction * a = new SieveAction( SieveAction::FileInto );
                a->setMailbox( i->mailbox );
                i->actions.append( a );
                log( "Keeping message in " + i->mailbox->name().utf8() );
            }
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
    else if ( c->identifier() == "reject" ||
              c->identifier() == "ereject" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Reject );
        actions.append( a );
    }
    else if ( c->identifier() == "fileinto" ) {
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
            // next line is dubious. if there's an error here, but
            // another command cancels implicit keep, then this forces
            // the keep back on. is this the right thing to do?
            explicitKeep = true;
            done = true;
        }
        else {
            implicitKeep = false;
        }
        actions.append( a );
    }
    else if ( c->identifier() == "redirect" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Redirect );
        UString arg = c->arguments()->takeString( 1 );
        AddressParser ap( arg.utf8() );
        a->setRecipientAddress( ap.addresses()->first() );
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

        // can't execute vacation without looking at the message
        if ( !d->message )
            return false;

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
        if ( !from && d->currentRecipient ) {
            from = d->currentRecipient->address;
        }
        if ( from && d->currentRecipient->user ) {
            Address * a = d->currentRecipient->user->address();
            if ( a->localpart().lower() == from->localpart().lower() &&
                 a->domain().lower() == from->domain().lower() )
                from = a;
        }

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
        String slp = d->sender->localpart().lower();
        if ( d->sender->type() != Address::Normal )
            wantToReply = false;
        else if ( slp.startsWith( "owner-" ) )
            wantToReply = false;
        else if ( slp.endsWith( "-request" ) )
            wantToReply = false;
        else if ( slp.contains( "-bounce" ) )
            wantToReply = false;
        else if ( slp == "subs-reminder" ||
                  slp == "root" || slp == "ftp" ||
                  slp == "www" || slp == "www-data" )
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

        // if we want to reply, we look for a display-name so the
        // reply's To field looks better.
        Address * to = d->sender;
        if ( wantToReply ) {
            List<Address>::Iterator i
                ( d->message->header()->addresses( HeaderField::From ) );
            while ( i && to == d->sender ) {
                if ( i->localpart() == to->localpart() &&
                     i->domain().lower() == to->domain().lower() &&
                     !i->name().isEmpty() )
                    to = i;
                ++i;
            }
        }

        // :handle
        UString handle = al->takeTaggedString( ":handle" );

        // reason
        UString reason = al->takeString( 1 );
        Injectee * reply = 0;

        String reptext;
        reptext.append( "From: " );
        reptext.append( from->toString() );
        reptext.append( "\r\n"
                        "To: " );
        reptext.append( to->toString() );
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
                       field( HeaderField::Received )->rfc822();
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
            reply = new Injectee;
            reply->parse( reptext );
        }
        else {
            if ( !reason.isAscii() )
                reptext.append( "Content-Type: text/plain; charset=utf-8\r\n"
                                "Mime-Version: 1.0\r\n" );
            reptext.append( "\r\n" );
            reptext.append( reason.utf8() );
            reply = new Injectee;
            reply->parse( reptext );
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
            HeaderField * mid
                = d->message->header()->field( HeaderField::MessageId );
            if ( mid ) {
                reply->header()->add( "In-Reply-To", mid->rfc822() );
                HeaderField * ref
                    = d->message->header()->field( HeaderField::References );
                if ( ref )
                    reply->header()->add( "References",
                                          ref->rfc822() + " " +
                                          mid->rfc822() );
                else
                    reply->header()->add( "References", mid->rfc822() );
            }
            else {
                // some senders don't add message-id, so we have to
                // leave out in-reply-to and references.
            }
            reply->addMessageId();
            SieveAction * a = new SieveAction( SieveAction::Vacation );
            actions.append( a );
            a->setMessage( reply );
            a->setSenderAddress( from );
            a->setRecipientAddress( d->sender );
            a->setHandle( handle );
            a->setExpiry( days );
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
        while ( i ) {
            uint hft = HeaderField::fieldType( i->ascii() );

            if ( ( hft > 0 && hft <= HeaderField::LastAddressField &&
                   !d->message->hasAddresses() ) ||
                 !d->message->hasHeaders() )
                return Undecidable;

            List<HeaderField>::Iterator hf( d->message->header()->fields() );
            while ( hf ) {
                if ( hf->name() == i->ascii() )
                    haystack->append( hf->value() );
                ++hf;
            }

            if ( t->identifier() == "exists" && haystack->isEmpty() )
                return False;

            ++i;
        }

        if ( t->identifier() == "exists" )
            return True;
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
                dt.setRfc822( hf->rfc822() );
        }
        else {
            dt.setCurrentTime();
        }

        if ( !t->dateZone().isEmpty() )
            dt.setTimezone( t->dateZone().ascii() );
        else
            dt.setLocalTimezone();

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
    false if \a address is not known, if the Sieve isn't ready() or if
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
    if ( d->injector && !d->injector->error().isEmpty() )
        return d->injector->error();
    return "";
}


/*! Returns true if the Sieve has finished evaluation (although not
    execution), and false if there's more to do before evaluation is
    complete. injected() is this function's bigger sister.
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


/*! Starts executing all the actions(), notifying \a handler when
    done.
*/

void Sieve::act( EventHandler * handler )
{
    if ( d->state )
        return;
    d->handler = handler;
    d->state = 1;
    execute();
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
    be forwarded.

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
                String s = a->recipientAddress()->lpdomain();
                if ( !uniq.contains( s ) ) {
                    uniq.append( s );
                    r->append( a->recipientAddress() );
                }
            }
            ++a;
        }
        ++i;
    }
    List<Address>::Iterator a( d->submissions );
    while ( a ) {
        String s = a->lpdomain();
        if ( !uniq.contains( s ) ) {
            uniq.append( s );
            r->append( a );
        }
        ++a;
    }
    return r;
}


/*! Returns true if this message has been rejected by (all of its)
    recipient(s), and false if it has no recipients or has been
    accepted by at least one.
*/

bool Sieve::rejected() const
{
    if ( d->recipients.isEmpty() )
        return false;
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


/*! Returns true if every injector created by this Sieve has finished
    its work. When ready() and done() and injected(), the Sieve is
    completely done.
*/

bool Sieve::injected() const
{
    if ( !d->injector )
        return false;
    if ( d->injector->done() )
        return true;
    return false;
}


/*! Returns a list of all vacation actions. The list may be empty, but
    it never is a null pointer.
*/

List<SieveAction> * Sieve::vacations() const
{
    List<SieveAction> * v = new List<SieveAction>;
    List<SieveData::Recipient>::Iterator r( d->recipients );
    while ( r ) {
        List<SieveAction>::Iterator a( r->actions );
        while ( a ) {
            if ( a->type() == SieveAction::Vacation )
                v->append( a );
            ++a;
        }
        ++r;
    }
    return v;
}
