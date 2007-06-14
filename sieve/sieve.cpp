// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieve.h"

#include "html.h"
#include "user.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "bodypart.h"
#include "mimefields.h"
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
        Recipient( Address * a, Mailbox * m, User * u, SieveData * data )
            : d( data ), address( a ), mailbox( m ),
              done( false ), ok( true ),
              implicitKeep( true ), explicitKeep( false ),
              sq( 0 ), script( new SieveScript ), user( u )
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
        String prefix;
        User * user;

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
    for the owner of \a destination. If \a user is non-null, Sieve
    will check that fileinto statement only file mail into mailboxes
    owned by \a user.

    If \a address is not a registered alias, Sieve will refuse mail to
    it.
*/

void Sieve::addRecipient( Address * address, Mailbox * destination,
                          User * user, SieveScript * script )
{
    SieveData::Recipient * r
        = new SieveData::Recipient( address, destination, user, d );
    d->currentRecipient = r;
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
    String arg;
    if ( c->arguments() &&
         c->arguments()->arguments() &&
         c->arguments()->arguments()->first() &&
         c->arguments()->arguments()->first()->stringList() &&
         !c->arguments()->arguments()->first()->stringList()->isEmpty() )
        arg = *c->arguments()->arguments()->first()->stringList()->first();

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
    } else if ( c->identifier() == "fileinto" ) {
        implicitKeep = false;
        SieveAction * a = new SieveAction( SieveAction::FileInto );
        String n = arg;
        if ( !arg.startsWith( "/" ) )
            n = prefix + arg;
        a->setMailbox( Mailbox::find( n ) );
        if ( !a->mailbox() ||
             ( user && user->id() != a->mailbox()->owner() ) ) {
            a = new SieveAction( SieveAction::Error );
            if ( !a->mailbox() )
                error = "No such mailbox: " + arg;
            else
                error = "Mailbox not owned by " +
                        user->login() + ": " + arg;
            if ( n != arg )
                error.append( " (" + n + ")" );
            a->setErrorMessage( error );
            implicitKeep = true;
            done = true;
        }
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
        explicitKeep = true;
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
    else if ( t->identifier() == "body" ) {
        if ( !d->message ) {
            return Undecidable;
        }
        else if ( t->bodyMatchType() == SieveTest::Rfc822 ) {
            haystack = new StringList;
            haystack->append( d->message->body() );
        }
        else {
            haystack = new StringList;
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
                    StringList::Iterator k( t->contentTypes() );
                    while ( k ) {
                        // this logic is based exactly on the draft.
                        if ( k->startsWith( "/" ) ||
                             k->endsWith( "/" ) ||
                             ( k->find( '/' ) >= 0 &&
                               k->find( k->find( '/' ) + 1 ) >= 0 ) ) {
                            // matches no types
                        }
                        else if ( k->contains( '/' ) ) {
                            // matches ->type()/->subtype()
                            if ( ct == k->lower() )
                                include = true;
                        }
                        else if ( k->isEmpty() ) {
                            // matches all types
                            include = true;
                        }
                        else {
                            // matches ->type();
                            if ( ct.startsWith( k->lower() + "/" ) )
                                include = true;
                        }

                        ++k;
                    }
                }
                if ( include ) {
                    if ( ct == "text/html" )
                        haystack->append( HTML::asText( i->text() ).utf8() );
                    else if ( ct.startsWith( "multipart/" ) )
                        haystack->append( "" ); // draft says prologue+epilogue
                    else if ( ct == "message/rfc822" )
                        haystack->append( i->message()->header()->asText() );
                    else if ( ct.startsWith( "text/" ) )
                        haystack->append( i->text().utf8() );
                    else
                        haystack->append( i->data() );
                }
                ++i;
            }
        }
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
                if ( s.contains( g ) )
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

bool Sieve::succeeded( Address * address ) const
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && i->ok;
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

void Sieve::setPrefix( Address * address, const String & prefix )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        i->prefix = prefix;
}
