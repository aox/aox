// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieve.h"

#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "stringlist.h"
#include "sievescript.h"
#include "sieveaction.h"
#include "addressfield.h"
#include "sieveproduction.h"

#include "listext.h" // XXX: fix this ugly matching thing

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
              done( false ), ok( true ), implicitKeep( true ),
              sq( 0 ), script( new SieveScript )
        {
            d->recipients.append( this );
        }

        SieveData * d;
        Address * address;
        Mailbox * mailbox;
        bool done;
        bool ok;
        bool implicitKeep;
        String result;
        List<SieveAction> actions;
        List<SieveCommand> pending;
        Query * sq;
        SieveScript * script;

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
    while ( it && it->address != a )
        ++it;
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
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( i->sq ) {
            Row * r = i->sq->nextRow();
            if ( r ) {
                i->sq = 0;
                i->script->parse( r->getString( "script" ) );
                List<SieveCommand>::Iterator c(i->script->topLevelCommands());
                while ( c ) {
                    i->pending.append( c );
                    ++c;
                }
            }
        }
        ++i;
    }
}


/*! Records that the envelope sender is \a address. */

void Sieve::setSender( Address * address )
{
    d->sender = address;
}


/*! Records that \a address is one of the recipients for this message,
    and that \a destination is where the mailbox should be stored by
    default. Sieve will use \a script as script, or if \a script is a
    not supplied (normally the case), Sieve looks up the active script
    for the owner of \a destination.
    
    If \a address is not a registered alias, Sieve will refuse mail to
    it.
*/

void Sieve::addRecipient( Address * address, Mailbox * destination,
                          SieveScript * script )
{
    SieveData::Recipient * r 
        = new SieveData::Recipient( address, destination, d );
    if ( script ) {
        r->script = script;
        List<SieveCommand>::Iterator c( script->topLevelCommands() );
        while ( c ) {
            r->pending.append( c );
            ++c;
        }
        return;
    }
        
    r->sq = new Query( "select scripts.script from scripts s, mailboxes m "
                       "where s.owner=m.owner "
                       "and m.id=$1"
                       "and s.active='t'",
                       this );
    r->sq->bind( 1, destination->id() );
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
            if ( i->pending.isEmpty() )
                i->done = true;
            if ( i->done && i->implicitKeep ) {
                SieveAction * a = new SieveAction( SieveAction::FileInto );
                a->setMailbox( i->mailbox );
                i->actions.append( a );
            }
        }
        ++i;
    }
}


bool SieveData::Recipient::evaluate( SieveCommand * c )
{
    String arg;
    if ( c->arguments() &&
         c->arguments()->arguments() &&
         c->arguments()->arguments()->first() && 
         c->arguments()->arguments()->first()->stringList() &&
         !c->arguments()->arguments()->first()->stringList()->isEmpty() )
        arg = *c->arguments()->arguments()->first()->stringList()->first();

    if ( c->identifier() == "if" ||
         c->identifier() == "elsif" ) {
        Result r = evaluate( c->arguments()->tests()->firstElement() );
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
    else if ( c->identifier() == "else" ) {
        // if we get here, we should evaluate
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
    } else if ( c->identifier() == "fileinto" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::FileInto );
        a->setMailbox( Mailbox::find( arg ) );
        actions.append( a );
    }
    else if ( c->identifier() == "redirect" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Redirect );
        AddressParser ap( arg );
        a->setAddress( ap.addresses()->first() );
        actions.append( a );
    } else if ( c->identifier() == "keep" ) {
        implicitKeep = false;
        // nothing needed
    } else if ( c->identifier() == "discard" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::Discard );
        actions.append( a );
    } else {
        // ?
    }
    return true;
}


static void addAddress( StringList * l, Address * a,
                        SieveTest::AddressPart p )
{
    String * s = new String;
    if ( p != SieveTest::Domain )
        s->append( a->localpart() );
    if ( p == SieveTest::All || p == SieveTest::NoAddressPart )
        s->append( "@" );
    if ( p != SieveTest::Localpart )
        s->append( a->domain() );
    l->append( s );
}


SieveData::Recipient::Result SieveData::Recipient::evaluate( SieveTest * t )
{
    StringList * haystack = 0;
    if ( t->identifier() == "address" ) {
        if ( !d->message )
            return Undecidable;
        haystack = new StringList;
        List<HeaderField>::Iterator hf( d->message->header()->fields() );
        while ( hf ) {
            if ( hf->type() <= HeaderField::LastAddressField &&
                 t->headers()->contains( hf->name() ) ) {
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
        haystack = new StringList;
        StringList::Iterator i( t->envelopeParts() );
        while ( i ) {
            if ( *i == "from" )
                addAddress( haystack, d->sender, t->addressPart() );
            else if ( *i == "to" )
                addAddress( haystack, address, t->addressPart() );
            ++i;
        }
    }
    else if ( t->identifier() == "exists" ||
              t->identifier() == "header" ) {
        if ( !d->message )
            return Undecidable;
        haystack = new StringList;
        StringList::Iterator i( t->headers() );
        Result r = True;
        while ( i ) {
            uint hft = HeaderField::fieldType( *i );
            if ( (hft > 0 && hft <= HeaderField::LastAddressField)
                 ? (!d->message->hasAddresses())
                 : (!d->message->hasHeaders()) )
                r = Undecidable;
            List<HeaderField>::Iterator hf( d->message->header()->fields() );
            while ( hf && hf->name() != *i )
                ++hf;
            if ( t->identifier() == "exists" ) {
                if ( !hf )
                    return False;
            }
            else {
                if ( hf )
                    haystack->append( hf->value() );
            }
            ++i;
        }
        if ( t->identifier() == "exists" )
            return r;
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
    else {
        // unknown test. wtf?
        return False;
    }

    StringList::Iterator h( haystack );
    while ( h ) {
        StringList::Iterator k( t->keys() );
        String s;
        switch ( t->comparator() ) {
        case SieveTest::IAsciiCasemap:
            s = h->lower();
            break;
        case SieveTest::IOctet:
            s = *h;
            break;
        }
        while ( k ) {
            String g;
            switch ( t->comparator() ) {
            case SieveTest::IAsciiCasemap:
                g = k->lower();
                break;
            case SieveTest::IOctet:
                g = *k;
                break;
            }
            switch ( t->matchType() ) {
            case SieveTest::Is:
                if ( s == g )
                    return True;
                break;
            case SieveTest::Contains:
                if ( s.contains( k ) )
                    return True;
                break;
            case SieveTest::Matches:
                if ( Listext::match( g, 0, s, 0 ) == 2 ) // XXX: fixme! please!
                    return True;
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

bool Sieve::succeeded( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && i->ok;
    return false;
}


/*! Returns true if delivery to \a address failed or will fail, and
    false if it succeeded or if evaluation is not yet complete.
*/

bool Sieve::failed( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && !i->ok;
    return false;
}


/*! Returns a single-line result string for use e.g. as SMTP/LMTP
    response. If neither failed() nor succeeded() returns true for \a
    address, the result of result() is undefined.
*/

String Sieve::result( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->result;
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
    return r;
}


/*! Returns true if this message has been rejected by (all of its)
    recipient(s), and false if it's been accepted by at least one.
*/

bool Sieve::rejected() const
{
    return false;
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
