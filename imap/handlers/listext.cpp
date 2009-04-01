// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "listext.h"

#include "estring.h"
#include "ustring.h"
#include "estringlist.h"
#include "ustringlist.h"
#include "imapparser.h"
#include "address.h"
#include "mailbox.h"
#include "query.h"
#include "dict.h"
#include "user.h"
#include "map.h"


class ListextData
    : public Garbage
{
public:
    ListextData():
        selectQuery( 0 ), permissionsQuery( 0 ),
        subscribed( 0 ),
        reference( 0 ),
        state( 0 ),
        extended( false ),
        returnSubscribed( false ), returnChildren( false ),
        selectSubscribed( false ), selectRemote( false ),
        selectRecursiveMatch( false )
    {}

    Query * selectQuery;
    Query * permissionsQuery;
    List<Mailbox> * subscribed;
    Mailbox * reference;
    EString referenceName;
    UStringList patterns;
    uint state;

    class Permissions
        : public Garbage
    {
    public:
        Permissions( Mailbox * m ): mailbox( m ), set( false ) {}
        Mailbox * mailbox;
        bool set;
        EString user;
        EString anyone;
    };

    Map<Permissions> permissions;

    Query * permissionFetcher;

    class Response
        : public Garbage
    {
    public:
        Response( Mailbox * m, const EString & r )
            : mailbox( m ), response ( r ) {}
        Mailbox * mailbox;
        EString response;
    };

    UDict<Response> responses;
    void addResponse( const UString & n, Response * r ) {
        UString k = n;
        k.append( (uint)0 );
        responses.insert( k.titlecased(), r );
    }

    bool extended;
    bool returnSubscribed;
    bool returnChildren;
    bool selectSubscribed;
    bool selectRemote;
    bool selectRecursiveMatch;
};


/*! \class Listext listext.h

    The Listext class implements the extended List command, ie. the
    List command from imap4rev1 with the extensions added since,
    particularly RFC 5258.

    Archiveopteryx does not support remote mailboxes, so the listext
    option to show remote mailboxes is silently ignored.
*/


/*!  Constructs an empty List handler. */

Listext::Listext()
    : d( new ListextData )
{
    setGroup( 4 );
}


/*! Note that the extensions are always parsed, even if no extension
    has been advertised using CAPABILITY.
*/

void Listext::parse()
{
    // list = "LIST" [SP list-select-opts] SP mailbox SP mbox-or-pat
    //        [SP list-return-opts]

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

   if ( ok() )
       log( "List " + d->reference->name().ascii() +
            " " + d->patterns.join( " " ).ascii() );
}


void Listext::execute()
{
    if ( d->state == 0 ) {
        if ( d->returnSubscribed || d->selectSubscribed ) {
            if ( !d->selectQuery ) {
                d->selectQuery
                    = new Query( "select mailbox from subscriptions "
                                 "where owner=$1", this );
                d->selectQuery->bind( 1, imap()->user()->id() );
                d->selectQuery->execute();
            }
            Row * r = 0;
            while ( (r=d->selectQuery->nextRow()) != 0 )
                d->subscribed->append(Mailbox::find( r->getInt( "mailbox" ) ));
        }

        if ( d->selectQuery ) {
            if ( !d->selectQuery->done() )
                return;
            if ( d->selectQuery->failed() ) {
                error( No,
                       "Unable to get list of selected mailboxes: " +
                       d->selectQuery->error() );
                setRespTextCode( "SERVERBUG" );
            }
        }
        d->state = 1;
    }

    if ( d->state == 1 ) {
        UStringList::Iterator it( d->patterns );
        while ( it ) {
            if ( it->isEmpty() && !d->extended ) {
                EString r;
                if ( d->reference == Mailbox::root() ) {
                    r = "LIST (\\noselect) \"/\" \"/\"";
                    d->addResponse(
                        Mailbox::root()->name(),
                        new ListextData::Response( d->reference, r ) );
                }
                else {
                    r = "LIST (\\noselect) \"/\" \"\"";
                    d->addResponse(
                        UString(),
                        new ListextData::Response( d->reference, r ) );
                }
            }
            else if ( it->startsWith( "/" ) ) {
                listChildren( Mailbox::root(), it->titlecased() );
            }
            else {
                listChildren( d->reference, it->titlecased() );
            }
            ++it;
        }
        d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->permissionsQuery ) {
            IntegerSet ids;
            UDict<ListextData::Response>::Iterator i( d->responses );
            while ( i ) {
                Mailbox * m = i->mailbox;
                ++i;
                while ( m != Mailbox::root() ) {
                    if ( m->id() && !m->deleted() ) {
                        ListextData::Permissions * p
                            = d->permissions.find( m->id() );
                        if ( !p ) {
                            p = new ListextData::Permissions( m );
                            d->permissions.insert( m->id(), p );
                            ids.add( m->id() );
                        }
                    }
                    m = m->parent();
                }
            }
            d->permissionsQuery
                = new Query( "select mailbox, identifier, rights "
                             "from permissions "
                             "where mailbox=any($1) "
                             "and (identifier='anyone' or identifier=$2)",
                             this );
            d->permissionsQuery->bind( 1, ids );
            d->permissionsQuery->bind( 2, imap()->user()->login() );
            d->permissionsQuery->execute();
        }

        while ( d->permissionsQuery &&
                d->permissionsQuery->hasResults() ) {
            Row * r = d->permissionsQuery->nextRow();
            Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
            if ( m ) {
                EString identifier = r->getEString( "identifier" );
                ListextData::Permissions * p = d->permissions.find( m->id() );
                if ( p ) {
                    p->set = true;
                    if ( identifier == "anyone" )
                        p->anyone = r->getEString( "rights" ) + " ";
                    else
                        p->user = r->getEString( "rights" ) + " ";
                }
            }
        }
        if ( d->permissionsQuery && !d->permissionsQuery->done() )
            return;
        d->state = 3;
    }

    if ( d->state == 3 ) {
        UDict<ListextData::Response>::Iterator i( d->responses );
        while ( i ) {
            Mailbox * m = i->mailbox;
            if ( m->owner() == imap()->user()->id() ) {
                respond( i->response );
            }
            else {
                EString r;
                bool set = false;
                while ( m && !set ) {
                    ListextData::Permissions * p
                        = d->permissions.find( m->id() );
                    if ( p && !p->user.isEmpty() )
                        r = p->user;
                    else if ( p && !p->anyone.isEmpty() )
                        r = p->anyone;
                    if ( p && p->set )
                        set = true;
                    m = m->parent();
                }
                if ( r.contains( 'l' ) || !set )
                    respond( i->response );
            }
            ++i;
        }
    }

    finish();
}


/*! Parses and remembers the return \a option, or emits a suitable
    error. \a option must be in lower case.*/

void Listext::addReturnOption( const EString & option )
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

void Listext::addSelectOption( const EString & option )
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


/*! Considers whether the mailbox \a m or any of its children may match
    the pattern \a p, and if so, emits list responses. (Calls itself
    recursively to handle children.)
*/

void Listext::list( Mailbox * m, const UString & p )
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

    switch( Mailbox::match( p, 0, m->name().titlecased(), s ) ) {
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

void Listext::listChildren( Mailbox * mailbox, const UString & pattern )
{
    List<Mailbox> * c = mailbox->children();
    if ( !c )
        return;

    List<Mailbox>::Iterator it( c );
    while ( it ) {
        list( it, pattern );
        ++it;
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
    EStringList a;

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

    EString name = imapQuoted( mailbox );

    EString ext = "";
    if ( childSubscribed ) {
        ext = " (";
        if ( childSubscribed )
            ext.append( "(\"childinfo\" (\"subscribed\"))" );
        ext.append( ")" );
    }

    EString r = "LIST (" + a.join( " " ) + ") \"/\" " + name + ext;
    d->addResponse( mailbox->name(), new ListextData::Response( mailbox, r ) );
}


/*! Parses a reference name, and logs an error if something is wrong. */

void Listext::reference()
{
    uint x = parser()->mark();
    d->reference = 0;
    EString s = parser()->astring();
    if ( s.isEmpty() ) {
        if ( imap()->user() )
            d->reference = imap()->user()->home();
    }
    else if ( s == "/" ) {
        d->reference = Mailbox::root();
    }
    else {
        parser()->restore( x );
        d->reference = Mailbox::obtain( mailboxName(), false );
    }
    if ( !d->reference )
        error( Bad, "Can't obtain reference name" );
}
