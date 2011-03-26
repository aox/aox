// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
        reference( 0 ),
        state( 0 ),
        extended( false ),
        returnSubscribed( false ), returnChildren( false ),
        selectSubscribed( false ), selectRemote( false ),
        selectRecursiveMatch( false )
    {}

    Query * selectQuery;
    Query * permissionsQuery;
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

    EString previousResponse;
    List<Response> responses;

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

   if ( ok() )
       log( "List " + d->reference->name().ascii() +
            " " + d->patterns.join( " " ).ascii() );
}


void Listext::execute()
{
    if ( d->state == 0 && d->patterns.count() == 1 &&
         d->patterns.first()->isEmpty() ) {
        EString r;
        if ( d->reference == Mailbox::root() )
            r = "LIST () \"/\" \"/\"";
        else
            r = "LIST () \"/\" \"\"";
        d->previousResponse = r;
        d->responses.append(
            new ListextData::Response( imap()->user()->inbox(), r ) );
        d->state = 2;
    }

    if ( d->state == 0 ) {
        d->selectQuery = new Query( "", this );
        uint bn = 1;
        EString sel;
        if ( d->selectSubscribed && d->selectRecursiveMatch ) {
            sel = "select mb.id, mb.name, s.id as sid, "
                  "exists(select cmb.id from mailboxes cmb "
                  "join subscriptions cs on"
                  " (cmb.id=cs.mailbox and cs.owner=$1) "
                  "where lower(mb.name)||'/'="
                  "lower(substring(cmb.name from 1 for length(mb.name)+1)))"
                  " as csub "
                  "from mailboxes mb "
                  "left join subscriptions s on"
                  " (mb.id=s.mailbox and s.owner=$1) "
                  "where ";
            d->selectQuery->bind( 1, imap()->user()->id() );
            bn = 2;
        }
        else if ( d->selectSubscribed ) {
            sel = "select mb.id, mb.name, s.id as sid from mailboxes mb "
                  "join subscriptions s on (mb.id=s.mailbox and s.owner=$1) "
                  "where ";
            d->selectQuery->bind( 1, imap()->user()->id() );
            bn = 2;
        }
        else {
            sel = "select mb.id, mb.name";
            if ( d->returnSubscribed ) {
                sel.append( ", s.id as sid from mailboxes mb "
                            "left join subscriptions s on"
                            " (mb.id=s.mailbox and s.owner=$1)" );
                d->selectQuery->bind( 1, imap()->user()->id() );
                bn = 2;
            }
            else {
                sel.append( " from mailboxes mb" );
            }
            sel.append( " where " );
        }
        EStringList conditions;
        UStringList::Iterator i( d->patterns );
        bool first = true;
        while ( i ) {
            if ( !first )
                sel.append( " or " );
            first = false;
            UString p = *i;
            if ( !p.startsWith( "/" ) ) {
                p = d->reference->name();
                if ( !i->isEmpty() ) {
                    p.append( "/" );
                    p.append( *i );
                }
            }
            UStringList constparts;
            uint n = 0;
            uint wn = 0;
            while ( n <= p.length() ) {
                if ( n >= p.length() || p[n] == '%' || p[n] == '*' ) {
                    constparts.append( p.mid( wn, n-wn ) );
                    n++;
                    while ( p[n] == '%' || p[n] == '*' )
                        n++;
                    wn = n;
                }
                else {
                    n++;
                }
            }
            if ( constparts.isEmpty() ) {
                sel.append( "true" );
            }
            else {
                sel.append( "mb.name ilike " );
                UStringList::Iterator constpart( constparts );
                while ( constpart ) {
                    sel.append( "$" );
                    sel.appendNumber( bn );
                    d->selectQuery->bind( bn, *constpart );
                    bn++;
                    ++constpart;
                    if ( constpart )
                        sel.append( "||'%'||" );
                }
            }
            ++i;
        }
        sel.append( " order by lower(mb.name)||' '" );
        d->selectQuery->setString( sel );
        d->selectQuery->execute();

        d->state = 1;
    }

    if ( d->state == 1 ) {
        while ( d->selectQuery->hasResults() ) {
            Row * r = d->selectQuery->nextRow();
            UString mn = r->getUString( "name" );
            bool matches = false;

            UStringList::Iterator i( d->patterns );
            while ( i && !matches ) {
                uint s = 0;
                if ( (*i)[0] != '*' && (*i)[0] != '/' ) {
                    s = d->reference->name().length();
                    if ( !i->isEmpty() && !d->reference->name().endsWith( "/" ) )
                        s++;
                }
                if ( Mailbox::match( i->titlecased(), 0,
                                     mn.titlecased(), s ) == 2 )
                    matches = true;
                ++i;
            }
            if ( matches )
                makeResponse( r );
        }
        if ( d->selectQuery->done() )
            d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->permissionsQuery ) {
            IntegerSet ids;
            List<ListextData::Response>::Iterator i( d->responses );
            while ( i ) {
                Mailbox * m = i->mailbox;
                ++i;
                while ( m ) {
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
            if ( !ids.isEmpty() ) {
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
        List<ListextData::Response>::Iterator i( d->responses );
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
        finish();
    }
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


/*! Sends a LIST or LSUB response for \a row.
*/

void Listext::makeResponse( Row * row )
{
    Mailbox * mailbox = Mailbox::find( row->getInt( "id" ) );
    if ( !mailbox )
        return;

    EStringList a;

    // add the easy mailbox attributes
    if ( mailbox->deleted() )
        a.append( "\\nonexistent" );
    if ( mailbox->deleted() )
        a.append( "\\noselect" );
    if ( mailbox->hasChildren() )
        a.append( "\\haschildren" );
    else if ( !mailbox->deleted() )
        a.append( "\\hasnochildren" );
    if ( mailbox->view() )
        a.append( "\\view" );

    // then there's subscription
    bool include = false;
    EString ext = "";
    if ( row->hasColumn( "sid" ) && !row->isNull( "sid" ) ) {
        a.append( "\\subscribed" );
        include = true;
    }
    if ( row->hasColumn( "csub" ) && row->getBoolean( "csub" ) ) {
        ext = ( " ((\"childinfo\" (\"subscribed\")))" );
        include = true;
    }

    if ( d->selectSubscribed && !include )
        return;

    if ( mailbox->deleted() && !mailbox->hasChildren() && !include )
        return;

    EString name = imapQuoted( mailbox );

    EString r = "LIST (" + a.join( " " ) + ") \"/\" " + name + ext;

    if ( r == d->previousResponse )
        return;

    d->previousResponse = r;
    d->responses.append( new ListextData::Response( mailbox, r ) );
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
