#include "listext.h"

#include "string.h"
#include "stringlist.h"


class ListextData
{
public:
    StringList selections;
    String mailbox;
    StringList patterns;
    StringList returns;
};


/*! \class Listext listext.h

    The Listext class implements the extended List command, ie. the
    List command from imap4rev1 with the extensions added since.

    The extension grammar is intentionally kept minimal, since it's
    still a draft. Currently based on draft-ietf-imapext-list-extensions-09.
*/


/*!  Constructs an empty List handler. */

Listext::Listext()
    : d( new ListextData )
{
}


/*! \reimp

    Note that the extensions are always parsed, even if the no
    extension has been advertised using CAPABILITY.
*/

void Listext::parse()
{
    // list = "LIST" [SP list-select-opts] SP mailbox SP mbox_or_pat

    if ( present( "(" ) ) {
        // list-select-opts = "(" [list-select-option 
        //                    *(SP list-select-option)] ")"
        // list-select-option = "SUBSCRIBED" / "REMOTE" / "MATCHPARENT" /
        //                      option-extension
        d->selections.append( atom() );
        while ( present( " " ) )
            d->selections.append( atom() );
        require( ")" );
    }

    d->mailbox = astring();
    space();

    // mbox_or_pat = list-mailbox / patterns
    // patterns = "(" list-mailbox *(list-mailbox) ")"
    if ( present( "(" ) ) {
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
        d->returns.append( atom() );
        while ( present( " " ) )
            d->returns.append( atom() );
        require( ")" );
    }
    end();
}


/*! \reimp */

void Listext::execute()
{
    
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
    return result;
}
