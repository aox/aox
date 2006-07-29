// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "listext.h"

#include "string.h"
#include "stringlist.h"
#include "address.h"
#include "mailbox.h"
#include "query.h"
#include "user.h"
#include "map.h"


class ListextData
    : public Garbage
{
public:
    ListextData():
        selectQuery( 0 ),
        subscribed( 0 ),
        postAddressQuery( 0 ),
        postAddresses( 0 ),
        reference( 0 ),
        extended( false ),
        returnSubscribed( false ), returnChildren( false ),
        returnPostAddress( false ),
        selectSubscribed( false ), selectRemote( false ),
        selectRecursiveMatch( false )
    {}

    Query * selectQuery;
    List<Mailbox> * subscribed;
    Query * postAddressQuery;
    Map<Address> * postAddresses;
    Mailbox * reference;
    String referenceName;
    StringList patterns;

    bool extended;
    bool returnSubscribed;
    bool returnChildren;
    bool returnPostAddress;
    bool selectSubscribed;
    bool selectRemote;
    bool selectRecursiveMatch;
};


/*! \class Listext listext.h

    The Listext class implements the extended List command, ie. the
    List command from imap4rev1 with the extensions added since.

    The extension grammar is intentionally kept minimal, since it's
    still a draft. Currently based on
    draft-ietf-imapext-list-extensions-13.

    Archiveopteryx does not support remote mailboxes, so the listext
    option to show remote mailboxes is silently ignored.
*/


/*!  Constructs an empty List handler. */

Listext::Listext()
    : d( new ListextData )
{
    setGroup( 4 );
}


/*! Note that the extensions are always parsed, even if the no
    extension has been advertised using CAPABILITY.
*/

void Listext::parse()
{
    // list = "LIST" [SP list-select-opts] SP mailbox SP mbox-or-pat

    space();

    if ( present( "(" ) ) {
        d->extended = true;
        // list-select-opts = "(" [list-select-option
        //                    *(SP list-select-option)] ")"
        // list-select-option = "SUBSCRIBED" / "REMOTE" / "MATCHPARENT" /
        //                      option-extension
        addSelectOption( atom().lower() );
        while ( present( " " ) )
            addSelectOption( atom().lower() );
        require( ")" );
        space();
    }

    reference();
    space();

    // mbox-or-pat = list-mailbox / patterns
    // patterns = "(" list-mailbox *(SP list-mailbox) ")"
    if ( present( "(" ) ) {
        d->extended = true;

        d->patterns.append( listMailbox() );
        while ( present( " " ) )
            d->patterns.append( listMailbox() );
        require( ")" );
    }
    else {
        d->patterns.append( listMailbox() );
    }

    // list-return-opts = "RETURN (" [return-option *(SP return-option)] ")"
    if ( present( " return (" ) ) {
        d->extended = true;

        addReturnOption( atom().lower() );
        while ( present( " " ) )
            addReturnOption( atom().lower() );
        require( ")" );
    }
    end();

    if ( d->selectRecursiveMatch && !d->selectSubscribed )
        error( Bad, "Recursivematch alone won't do" );

    if ( d->selectSubscribed )
        d->returnSubscribed = true;

    if ( d->returnSubscribed )
        d->subscribed = new List<Mailbox>;

    if ( d->returnPostAddress )
        d->postAddresses = new Map<Address>;

    if ( ok() )
        log( "List " + d->reference->name() + " " + d->patterns.join( " " ) );
}


void Listext::execute()
{
    if ( d->returnSubscribed || d->selectSubscribed ) {
        if ( !d->selectQuery ) {
            d->selectQuery = new Query( "select mailbox from subscriptions "
                                        "where owner=$1", this );
            d->selectQuery->bind( 1, imap()->user()->id() );
            d->selectQuery->execute();
        }
        Row * r = 0;
        while ( (r=d->selectQuery->nextRow()) != 0 )
            d->subscribed->append( Mailbox::find( r->getInt( "mailbox" ) ) );
    }
    if ( d->returnPostAddress ) {
        if ( !d->postAddressQuery ) {
            d->postAddressQuery
                = new Query( "select a.localpart, a.domain, al.mailbox "
                             "from addresses a, aliases al "
                             "where a.id = al.address",
                             this );
            d->postAddressQuery->execute();
        }
        Row * r = 0;
        while ( (r=d->postAddressQuery->nextRow()) != 0 ) {
            Address * a = new Address( "", r->getString( "localpart" ),
                                       r->getString( "domain" ) );
            uint mailbox = r->getInt( "mailbox" );
            d->postAddresses->insert( mailbox, a );
        }
    }

    if ( d->selectQuery ) {
        if ( !d->selectQuery->done() )
            return;
        if ( d->selectQuery->failed() )
            respond( "* NO Unable to get list of selected mailboxes: " +
                     d->selectQuery->error() );
    }
    if ( d->postAddressQuery ) {
        if ( !d->postAddressQuery->done() )
            return;
        if ( d->postAddressQuery->failed() )
            respond( "* NO Unable to get list of inboxes: " +
                     d->postAddressQuery->error() );
    }

    StringList::Iterator it( d->patterns );
    while ( it ) {
        if ( it->isEmpty() )
            respond( "LIST () \"/\" \"\"" );
        else if ( it->startsWith( "/" ) )
            listChildren( Mailbox::root(), *it );
        else
            listChildren( d->reference, *it );
        ++it;
    }

    finish();
}


/*! Parses and remembers the return \a option, or emits a suitable
    error. \a option must be in lower case.*/

void Listext::addReturnOption( const String & option )
{
    if ( option == "subscribed" )
        d->returnSubscribed = true;
    else if ( option == "children" )
        d->returnChildren = true;
    else if ( option == "postaddress" )
        d->returnPostAddress = true;
    else
        error( Bad, "Unknown return option: " + option );
}


/*! Parses the selection \a option, or emits a suitable error. \a
    option must be lower-cased. */

void Listext::addSelectOption( const String & option )
{
    if ( option == "subscribed" )
        d->selectSubscribed = true;
    else if ( option == "remote" )
        d->selectRemote = true;
    else if ( option == "recursivematch" )
        d->selectRecursiveMatch = true;
    else
        error( Bad, "Unknown selection option: " + option );
}


/*! This extremely slow pattern matching helper checks that \a pattern
    (starting at character \a p) matches \a name (starting at
    character \a n), and returns 2 in case of match, 1 if a child of
    \a name might match, and 0 if neither is the case.
*/

uint Listext::match( const String & pattern, uint p,
                     const String & name, uint n )
{
    uint r = 0;
    while ( p <= pattern.length() ) {
        if ( pattern[p] == '*' || pattern[p] == '%' ) {
            bool star = false;
            while ( pattern[p] == '*' || pattern[p] == '%' ) {
                if ( pattern[p] == '*' )
                    star = true;
                p++;
            }
            uint i = n;
            if ( star )
                i = name.length();
            else
                while ( i < name.length() && name[i] != '/' )
                    i++;
            while ( i >= n ) {
                uint s = match( pattern, p, name, i );
                if ( s == 2 )
                    return 2;
                if ( s == 1 )
                    r = 1;
                i--;
            }
        }
        else if ( p == pattern.length() && n == name.length() ) {
            // ran out of pattern and name at the same time. success.
            return 2;
        }
        else if ( pattern[p] == name[n] ) {
            // nothing. proceed.
            p++;
        }
        else if ( pattern[p] == '/' && n == name.length() ) {
            // we ran out of name and the pattern wants a child.
            return 1;
        }
        else {
            // plain old mismatch.
            return r;
        }
        n++;
    }
    return r;
}


/*! Considers whether the mailbox \a m or any of its children may match
    the pattern \a p, and if so, emits list responses. (Calls itself
    recursively to handle children.)
*/

void Listext::list( Mailbox * m, const String & p )
{
    if ( !m )
        return;

    bool matches = false;
    bool matchChildren = false;

    uint s = 0;
    if ( p[0] != '/' && p[0] != '*' ) {
        s = d->reference->name().length();
        if ( !d->reference->name().endsWith( "/" ) )
            s++;
    }

    switch( match( p, 0, m->name().lower(), s ) ) {
    case 0:
        break;
    case 1:
        matchChildren = true;
        break;
    default:
        matchChildren = true;
        matches = true;
        break;
    }

    if ( matches ) {
        if ( d->selectSubscribed ) {
            List<Mailbox>::Iterator it( *d->subscribed );
            while ( it && it != m )
                ++it;
            if ( !it )
                matches = false;
        }
        else {
            if ( ( m->synthetic() || m->deleted() ) && !m->hasChildren() )
                matches = false;
        }
    }


    if ( matches )
        sendListResponse( m );

    if ( matchChildren )
        listChildren( m, p );
}


/*! Calls list() for each child of \a mailbox using \a pattern. */

void Listext::listChildren( Mailbox * mailbox, const String & pattern )
{
    List<Mailbox> * c = mailbox->children();
    if ( c ) {
        List<Mailbox>::Iterator it( c );
        while ( it ) {
            list( it, pattern );
            ++it;
        }
    }
}


/*! Sends a LIST or LSUB response for \a mailbox.

    Open issue: If \a mailbox is the inbox, what should we send?
    INBOX, or the fully qualified name, or the name relative to the
    user's home directory?
*/

void Listext::sendListResponse( Mailbox * mailbox )
{
    if ( !mailbox )
        return;

    bool childSubscribed = false;
    StringList a;

    // add the easy mailbox attributes
    if ( mailbox->deleted() )
        a.append( "\\nonexistent" );
    if ( mailbox->synthetic() || mailbox->deleted() )
        a.append( "\\noselect" );
    if ( mailbox->hasChildren() )
        a.append( "\\haschildren" );
    else if ( !mailbox->deleted() )
        a.append( "\\hasnochildren" );
    if ( mailbox->view() )
        a.append( "\\view" );

    // then there's subscription, which isn't too pretty
    if ( d->subscribed ) {
        List<Mailbox>::Iterator it( *d->subscribed );
        while ( it && it != mailbox )
            ++it;
        if ( it )
            a.append( "\\subscribed" );

        if ( d->selectRecursiveMatch ) {
            // recursivematch is hard work... almost O(world)
            it = d->subscribed->first();
            while ( it && !childSubscribed ) {
                Mailbox * p = it;
                while ( p && p != mailbox )
                    p = p->parent();
                if ( p && p != it )
                    childSubscribed = true;
                ++it;
            }
        }
    }

    // postaddress, on the other hand, is distinctly easy
    Address * postAddress = 0;
    if ( d->postAddresses )
        postAddress = d->postAddresses->find( mailbox->id() );

    String name = mailbox->name();
    String refName = d->reference->name();
    if ( !refName.endsWith( "/" ) )
        refName.append( "/" );
    if ( name.startsWith( refName ) )
        name = d->referenceName + mailbox->name().mid( refName.length() );
    name = imapQuoted( name, AString );

    String ext = "";
    if ( childSubscribed || d->returnPostAddress ) {
        ext = " (";
        if ( childSubscribed )
            ext.append( "(\"childinfo\" (\"subscribed\"))" );
        if ( !d->returnPostAddress )
            ; // don't return postaddress information
        else if ( postAddress )
            ext.append( "(\"postaddress\" " +
                        imapQuoted( postAddress->toString(), NString ) + ")" );
        else
            ext.append( "(\"postaddress\" NIL)" );
        ext.append( ")" );
    }

    respond( "LIST (" + a.join( " " ) + ") \"/\" " + name + ext );
}


/*! Parses a reference name, and logs an error if something is wrong. */

void Listext::reference()
{
    String name = astring();
    d->referenceName = name;
    if ( !d->referenceName.isEmpty() && !d->referenceName.endsWith( "/" ) )
        d->referenceName.append( "/" );

    if ( name.length() > 1 && name.endsWith( "/" ) )
        name.truncate( name.length()-1 );

    if ( name[0] == '/' )
        d->reference = Mailbox::obtain( name, false );
    else if ( name.isEmpty() )
        d->reference = imap()->user()->home();
    else
        d->reference
            = Mailbox::obtain( imap()->user()->home()->name() + "/" + name,
                               false );

    if ( !d->reference )
        error( No, "Cannot find reference name " + name );
}
