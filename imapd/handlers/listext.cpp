// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "listext.h"

#include "string.h"
#include "stringlist.h"
#include "mailbox.h"


class ListextData
{
public:
    ListextData():
        responses( 0 ),
        extended( false ),
        returnSubscribed( false ), returnChildren( false ),
        selectSubscribed( false ), selectRemote( false ),
        selectMatchParent( false )
    {}

    String mailbox;
    StringList patterns;

    uint responses;

    bool extended;
    bool returnSubscribed;
    bool returnChildren;
    bool selectSubscribed;
    bool selectRemote;
    bool selectMatchParent;
};


/*! \class Listext listext.h

    The Listext class implements the extended List command, ie. the
    List command from imap4rev1 with the extensions added since.

    The extension grammar is intentionally kept minimal, since it's
    still a draft. Currently based on draft-ietf-imapext-list-extensions-09.

    Mailstore does not support remote mailboxes, so the listext option
    to show remote mailboxes is silently ignored.
*/


/*!  Constructs an empty List handler. */

Listext::Listext()
    : d( new ListextData )
{
}


/*! Note that the extensions are always parsed, even if the no
    extension has been advertised using CAPABILITY.
*/

void Listext::parse()
{
    // list = "LIST" [SP list-select-opts] SP mailbox SP mbox_or_pat

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
    }

    d->mailbox = astring();
    space();

    // mbox_or_pat = list-mailbox / patterns
    // patterns = "(" list-mailbox *(list-mailbox) ")"
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
    if ( present( "return (" ) ) {
        d->extended = true;

        addReturnOption( atom().lower() );
        while ( present( " " ) )
            addReturnOption( atom().lower() );
        require( ")" );
    }
    end();
}


void Listext::execute()
{
    if ( d->selectMatchParent && !d->selectRemote && !d->selectSubscribed ) {
        error( Bad, "MATCH-PARENT is not valid on its own" );
        return;
    }

    // find the common bits of the patterns

    String prefix;
    bool first = true;
    StringList::Iterator it( d->patterns.first() );
    while ( it ) {
        String pattern = *it;
        ++it;
        if ( first ) {
            prefix = pattern;
            first = false;
        }
        else if ( !pattern.startsWith( prefix ) ) {
            uint i = 0;
            while ( pattern[i] == prefix[i] )
                i++;
            prefix = prefix.mid( 0, i );
        }
    }

    // only components before the first wildcard may be used

    if ( !prefix.isEmpty() ) {
        uint i = prefix.find( '%' );
        uint j = prefix.find( '*' );
        if ( i < 0 )
            i = j;
        if ( j < i && j >= 0 )
            i = j;
        while ( i > 0 && prefix[i] != '/' )
            i--;
        if ( i == 0 )
            prefix = "/";
        else
            prefix = prefix.mid( 0, i );
    }

    // good. we're ready to start listing mailboxes.
    Mailbox * root = Mailbox::find( prefix );
    if ( root ) {
        List<Mailbox> * c = root->children();
        if ( c ) {
            List<Mailbox>::Iterator it( c->first() );
            while ( it ) {
                list( it );
                ++it;
            }
        }
    }
    finish();
}


/*! Parses and returns a list-mailbox. This is the same as an atom(),
    except that the three exceptions %, * and ] are accepted.
*/

String Listext::listMailbox()
{
    String result;
    char c = nextChar();
    while ( c > ' ' && c < 127 &&
            c != '(' && c != ')' && c != '{' &&
            c != '"' && c != '\\' )
        {
            result.append( c );
            step();
            c = nextChar();
        }
    if ( result.isEmpty() )
        error( Bad, "list-mailbox expected, saw: " + following() );

    // make sure the pattern is fully qualified
    if ( result[0] != '/' ) {
        if ( d->mailbox.isEmpty() )
            result = "/" + result;
        else if ( d->mailbox[d->mailbox.length()-1] == '/' )
            result = d->mailbox + result;
        else
            result = d->mailbox + "/" + result;
    }
    respond( "Will match: " + result, Untagged );
    return result;
}


/*! Parses and remembers the return \a option, or emits a suitable
    error. \a option must be in lower case.*/

void Listext::addReturnOption( const String & option )
{
    if ( option == "subscribed" )
        d->returnSubscribed = true;
    else if ( option == "children" )
        d->returnChildren = true;
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
    else if ( option == "matchparent" )
        d->selectMatchParent = true;
    else
        error( Bad, "Unknown selection option: " + option );
}


/* this slow-as-hell pattern matching helper checks that pattern
   (starting at p) matches name (starting at n), and returns 2 in case
   of match, 1 if a child of name might match, and 0 if neither is the
   case.
*/

static uint match( const String & pattern, uint p,
                   const String & name, uint n )
{
    bool one = false;
    while ( p < pattern.length() ) {
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
            while ( i >= n && i > 0 ) {
                uint r = match( pattern, p, name, i );
                if ( r == 2 )
                    return 2;
                if ( r == 1 )
                    one = true;
                i--;
            }
        }
        else if ( pattern[p] == name[n] ) {
            // nothing. proceed.
        }
        else if ( pattern[p] == '/' && n > name.length() ) {
            // we ran out of name and the pattern wants a child.
            return 1;
        }
        else {
            // plain old mismatch.
            return 0;
        }
        p++;
        n++;
    }
    if ( n >= name.length() )
        return 2;
    if ( one )
        return 1;
    return 0;
}


/*! Considers whether \a mailbox or any of its children may match any
    of the specified patterns, and if so, emits list responses. (Calls
    itself recursively to handle children.)
*/

void Listext::list( Mailbox * mailbox )
{
    if ( !mailbox )
        return;
    String name = mailbox->name();
    StringList::Iterator it( d->patterns.first() );
    bool matchChildren = false;
    bool matches = false;
    while ( it && !matches ) {
        String pattern = *it;
        ++it;
        switch( match( pattern, 0, name, 0 ) ) {
        case 0:
            break;
        case 1:
            matchChildren = true;
            break;
        default:
            matches = true;
            matchChildren = true;
            break;
        }
    }
    uint responses = d->responses;

    if ( matchChildren ) {
        List<Mailbox> * c = mailbox->children();
        if ( c ) {
            List<Mailbox>::Iterator it( c->first() );
            while ( it ) {
                list( it );
                it++;
            }
        }
    }

    if ( matches )
        sendListResponse( mailbox ); // simple case
    else if ( responses < d->responses && d->selectMatchParent )
        sendListResponse( mailbox ); // some child matched and we matchparent
    else if ( responses < d->responses && mailbox->deleted() )
        sendListResponse( mailbox ); // some child matched and it's deleted
}


/*! Sends a list response for \a mailbox. */

void Listext::sendListResponse( Mailbox * mailbox )
{
    if ( !mailbox )
        return;

    StringList a;

    // set up the underlying flags
    bool exists = true;
    if ( mailbox->synthetic() || mailbox->deleted() )
        exists = false;
    bool children = false;
    if ( mailbox->children() && !mailbox->children()->isEmpty() )
        children = true;
    // matchparent also needs some flags from the caller

    // translate those flags into mailbox attributes
    if ( !exists )
        a.append( "\\noselect" );
    if ( children )
        a.append( "\\haschildren" );
    else
        a.append( "\\hasnochildren" );

    respond( "LIST (" + a.join( " " ) + ") \"/\" " + mailbox->name() );
    d->responses++;
}
