// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "selector.h"

#include "utf.h"
#include "flag.h"
#include "date.h"
#include "session.h"
#include "mailbox.h"
#include "stringlist.h"
#include "annotation.h"
#include "field.h"
#include "user.h"


static uint lmatch( const String &, uint, const String &, uint );


class SelectorData
    : public Garbage
{
public:
    SelectorData()
        : f( Selector::NoField ), a( Selector::None ), mboxId( 0 ),
          placeholder( 0 ), query( 0 ), parent( 0 ),
          children( new List< Selector > ),
          session( 0 ),
          needDateFields( false ),
          needHeaderFields( false ),
          needAddresses( false ),
          needAddressFields( false ),
          needAnnotations( false ),
          needPartNumbers( false ),
          needBodyparts( false )
    {}

    Selector::Field f;
    Selector::Action a;

    String error;

    String s8;
    String s8b;
    UString s16;
    MessageSet s;
    uint n;

    uint mboxId;
    int placeholder;
    Query * query;

    Selector * parent;
    List< Selector > * children;
    Session * session;
    User * user;

    // XXX: eek! this is just a set of integers supporting idempotent
    // insertion.
    MessageSet needFlags;

    bool needDateFields;
    bool needHeaderFields;
    bool needAddresses;
    bool needAddressFields;
    bool needAnnotations;
    bool needPartNumbers;
    bool needBodyparts;
};


/*! \class Selector selector.h

    This class represents a set of conditions to select messages from
    a mailbox.

    The Selector class represents a single condition in a search,
    which is either a leaf condition or an AND/OR operator.

    The class can simplify() and regularize itself, such that all
    equivalent search inputs give the same result, and and it can
    express itself in a form amenable to testing. Rather simple.
*/


/*! Creates a new root "And" selector. */

Selector::Selector()
    : d( new SelectorData )
{
    d->a = And;
}


/*! Creates a selector with Field \a f, Action \a a, and the integer
    value \a n.
*/

Selector::Selector( Field f, Action a, uint n )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->n = n;
}


/*! Creates a selector with Field \a f, Action \a a, and the string
    value \a s.
*/

Selector::Selector( Field f, Action a, const String &s )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
}


/*! Creates a selector with Field \a f, Action \a a, and the UString
    value \a u.
*/

Selector::Selector( Field f, Action a, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s16 = u;
}


/*! Creates a selector with Field \a f, Action \a a, the String value
    \a s, and the UString value \a u.
*/

Selector::Selector( Field f, Action a, const String &s, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s16 = u;
}


/*! Creates a selector with Field \a f, Action \a a, the String values
    \a s and \a t, and the UString value \a u.
*/

Selector::Selector( Field f, Action a, const String &s,
                    const String &t, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s8b = t;
    d->s16 = u;
}


/*! Creates a selector from the MessageSet \a s. */

Selector::Selector( const MessageSet &s )
    : d( new SelectorData )
{
    d->f = Uid;
    d->a = Contains;
    d->s = s;
}


/*! Creates a selector with Action \a a. */

Selector::Selector( Action a )
    : d( new SelectorData )
{
    d->f = NoField;
    d->a = a;
}


/*! Returns the ultimate parent of this Selector. */

const Selector * Selector::root() const
{
    const Selector * p = this;

    while ( p->parent() )
        p = p->parent();

    return p;
}


/*! Returns the parent of this Selector, or 0 if it is the root. */

const Selector * Selector::parent() const
{
    return d->parent;
}


/*! Adds the Selector \a s to the list of this Selector's children. */

void Selector::add( Selector * s )
{
    s->d->parent = this;
    d->children->append( s );
}


/*! Returns the next integer from a monotonically increasing sequence on
    each call. The first value is 1. (This is used to construct the $n
    placeholder names in queries.)
*/

uint Selector::placeHolder()
{
    root()->d->placeholder++;
    return root()->d->placeholder;
}


/*! Records \a s as an error during the construction of this Selector
    tree. Only the first error in a tree is recorded, and it is recorded
    at the root of the tree (rather than the node where it occurred).
*/

void Selector::setError( const String &s )
{
    if ( root()->d->error.isEmpty() )
        root()->d->error = s;
}


/*! This helper transforms this search conditions and all its children
    into a simpler form, if possible. There are three goals to this:

    1. Provide a regular search expression, so that we can eventually
    detect and prepare statements for often-repeated searches.

    2. Ditto, so that we can test that equivalent input gives
    identical output.

    3. Avoid search expressions which would be horribly inefficient or
    just plain impossible for the RDBMS.
*/

void Selector::simplify()
{
    // not (not x) -> x
    if ( d->a == Not && d->children->first()->d->a == Not ) {
        Selector * again = d->children->first()->d->children->first();

        d->f = again->d->f;
        d->a = again->d->a;
        d->s8 = again->d->s8;
        d->s8b = again->d->s8b;
        d->s16 = again->d->s16;
        d->s = again->d->s;
        d->n = again->d->n;
        d->children = again->d->children;
    }

    if ( d->a == Larger && d->n == 0 ) {
        // > 0 matches everything
        d->a = All;
    }
    else if ( d->a == Contains ) {
        // x contains y may match everything
        switch ( d->f ) {
        case InternalDate:
        case Sent:
            d->a = None;
            break;
        case Header:
        case Body:
            if ( d->s16.isEmpty() )
                d->a = All;
            break;
        case Rfc822Size:
            break;
        case Flags:
            if ( d->s8 != "\\recent" && !Flag::find( d->s8 ) )
                d->a = None;
            break;
        case Uid:
            // if s contains all messages or is empty...
            if ( d->s.isEmpty() )
                d->a = None;
            // the All Messages case is harder.
            break;
        case Annotation:
            // can't simplify this
            break;
        case NoField:
            // contains is orthogonal to nofield, so this we cannot
            // simplify
            break;
        }
        // contains empty string too
    }
    else if ( d->a == Contains && d->f == Uid ) {
        if ( d->s.isEmpty() )
            d->a = None; // contains d->a set of nonexistent messages
        else if ( d->s.where() == "uid>=1" )
            d->a = All; // contains any messages at all
    }
    else if ( d->a == And ) {
        // zero-element and becomes all, "none and x" becomes none
        List< Selector >::Iterator i( d->children );
        while ( i && d->a == And ) {
            List< Selector >::Iterator p( i );
            ++i;
            p->simplify();
            if ( p->d->a == All )
                d->children->take( p );
            else if ( p->d->a == None )
                d->a = None;
        }
        if ( d->a == And && d->children->isEmpty() )
            d->a = All;

        if ( d->a != And )
            d->children->clear();
    }
    else if ( d->a == Or ) {
        // zero-element or becomes all, "all or x" becomes all
        List< Selector >::Iterator i( d->children );
        while ( i && d->a == Or ) {
            List< Selector >::Iterator p( i );
            ++i;
            p->simplify();
            if ( p->d->a == None )
                d->children->take( p );
            else if ( p->d->a == All )
                d->a = All;
        }
        if ( d->a == And && d->children->isEmpty() )
            d->a = All;

        if ( d->a != Or )
            d->children->clear();
    }
    if ( d->a == All || d->a == None )
        d->f = NoField;

    if ( d->a != And && d->a != Or )
        return;

    // an empty and/or means everything matches
    if ( d->children->isEmpty() ) {
        d->a = All;
        return;
    }

    // or (a or (b c)) -> or (a b c). ditto and.
    if ( d->children ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            List< Selector >::Iterator p( i );
            ++i;
            if ( p->d->a == d->a ) {
                List<Selector>::Iterator c( p->d->children );
                while ( c ) {
                    d->children->prepend( c );
                    ++c;
                }
                d->children->take( p );
            }
        }
    }

    // a single-element and/or can be removed and its argument substituted
    if ( d->children->count() == 1 ) {
        List< Selector >::Iterator p( d->children );

        d->f = p->d->f;
        d->a = p->d->a;
        d->s8 = p->d->s8;
        d->s8b = p->d->s8b;
        d->s16 = p->d->s16;
        d->s = p->d->s;
        d->children = p->d->children;
        return;
    }

    // at this point, for proper uniqueness, we ought to sort the
    // children, killing any duplicates in the process. then we'll
    // have a single query for each job. but that can wait. this will
    // do for testing.
}


/*! Returns a query representing this Selector or 0 if anything goes
    wrong, in which case error() contains a description of the problem.
    The Selector is expressed as SQL in the context of the specified
    \a user and \a session. The \a owner will be notified of query
    results. The \a mailbox to search is passed in separately, because
    we can't use the Session's mailbox while building views.
*/

Query * Selector::query( User * user, Mailbox * mailbox,
                         Session * session, EventHandler * owner )
{
    d->query = new Query( owner );
    d->user = user;
    d->session = session;
    d->placeholder = 0;
    d->mboxId = placeHolder();
    d->query->bind( d->mboxId, mailbox->id() );
    String q = "select distinct m.uid from messages m"
               " left join deleted_messages dm using (uid,mailbox)";
    String w = where();

    // make sure that any indirect joins below don't produce bad
    // syntax.  for example, if we look at bodyparts we have to join
    // it to messages via part_numbers.
    if ( d->needAddresses )
        d->needAddressFields = true;
    if ( d->needBodyparts )
        d->needPartNumbers = true;

    // flags are hard. we need to join in one relation per flag, so
    // that we don't accidentally think 'uid 123 has "\seen"' is
    // equivalent with 'uid 123 does not have "\deleted"'.
    if ( !d->needFlags.isEmpty() ) {
        uint i = 1;
        while ( i <= d->needFlags.count() ) {
            uint f = d->needFlags.value( i );
            String n = "f" + fn( f );
            i++;
            q.append( " left join flags " + n +
                      " on (m.mailbox=" + n + ".mailbox and m.uid=" + n +
                      ".uid and " + n + ".flag=" + fn( f ) + ")" );
        }
    }

    if ( d->needDateFields )
        q.append( " join date_fields df using (uid,mailbox)" );
    if ( d->needHeaderFields )
        q.append( " join header_fields hf using (uid,mailbox)" );
    if ( d->needAddressFields )
        q.append( " join address_fields af using (uid,mailbox)" );
    if ( d->needAddresses )
        q.append( " join addresses a on (af.address=a.id)" );
    if ( d->needAnnotations )
        q.append( " join annotations a using (uid,mailbox)" );
    if ( d->needPartNumbers )
        q.append( " join part_numbers pn using (uid,mailbox)" );
    if ( d->needBodyparts )
        q.append( " join bodyparts bp on (bp.id=pn.bodypart)" );

    q.append( " where m.mailbox=$" );
    q.append( fn( d->mboxId ) );
    q.append( " and dm.uid is null" );
    if ( !w.isEmpty() )
        q.append( " and " + w );
    q.append( " order by m.uid" );

    d->query->setString( q );
    return d->query;
}


/*! Gives an SQL string representing this condition.

    The string may include $n placeholders; where() and its helpers
    will bind them as required.
*/

String Selector::where()
{
    switch( d->f ) {
    case InternalDate:
        return whereInternalDate();
        break;
    case Sent:
        return whereSent();
        break;
    case Header:
        if ( d->s8.isEmpty() )
            return whereHeader();
        else
            return whereHeaderField();
        break;
    case Body:
        return whereBody();
        break;
    case Rfc822Size:
        return whereRfc822Size();
        break;
    case Flags:
        return whereFlags();
        break;
    case Uid:
        return whereUid();
        break;
    case Annotation:
        return whereAnnotation();
        break;
    case NoField:
        return whereNoField();
        break;
    }
    setError( "Internal error for " + debugString() );
    return "";
}

/*! This implements the INTERNALDATE part of where().
*/

String Selector::whereInternalDate()
{
    uint day = d->s8.mid( 0, 2 ).number( 0 );
    String month = d->s8.mid( 3, 3 );
    uint year = d->s8.mid( 7 ).number( 0 );
    // XXX: local time zone is ignored here
    Date d1;
    d1.setDate( year, month, day, 0, 0, 0, 0 );
    Date d2;
    d2.setDate( year, month, day, 23, 59, 59, 0 );
    uint n1 = placeHolder();
    root()->d->query->bind( n1, d1.unixTime() );
    uint n2 = placeHolder();
    root()->d->query->bind( n2, d2.unixTime() );

    if ( d->a == OnDate )
        return "(m.idate>=$" + fn( n1 ) + " and m.idate<=$" + fn( n2 ) + ")";
    else if ( d->a == SinceDate )
        return "m.idate>=$" + fn( n1 );
    else if ( d->a == BeforeDate )
        return "m.idate<=$" + fn( n2 );

    setError( "Cannot search for: " + debugString() );
    return "";
}


/*! This implements the SENTON/SENTBEFORE/SENTSINCE part of where().
*/

String Selector::whereSent()
{
    root()->d->needDateFields = true;

    uint day = d->s8.mid( 0, 2 ).number( 0 );
    String month = d->s8.mid( 3, 3 );
    uint year = d->s8.mid( 7 ).number( 0 );

    Date d1;
    d1.setDate( year, month, day, 0, 0, 0, 0 );
    uint n = placeHolder();

    if ( d->a == OnDate ) {
        d1.setDate( year, month, day, 23, 59, 59, 0 );
        root()->d->query->bind( n, d1.isoDate() + " " + d1.isoTime() );

        uint n2 = placeHolder();
        d1.setDate( year, month, day, 0, 0, 0, 0 );
        root()->d->query->bind( n2, d1.isoDate() );

        return "(df.value<=$" + fn( n ) + " and"
               " df.value>=$" + fn( n2 ) + ")";
    }
    else if ( d->a == SinceDate ) {
        root()->d->query->bind( n, d1.isoDate() );
        return "df.value>=$" + fn( n );
    }
    else if ( d->a == BeforeDate ) {
        root()->d->query->bind( n, d1.isoDate() );
        return "df.value<=$" + fn( n );
    }

    setError( "Cannot search for: " + debugString() );
    return "";
}


static String matchAny( int n )
{
    return "'%'||$" + fn( n ) + "||'%'";
}


static String q( const UString & orig )
{
    Utf8Codec c;
    String r( c.fromUnicode( orig ) );
    // escape % somehow?
    return r;
}


/*! This implements searches on a single header field.
*/

String Selector::whereHeaderField()
{
    d->s8 = d->s8.headerCased();

    uint f = 1;
    while ( f <= HeaderField::LastAddressField &&
            HeaderField::fieldName( (HeaderField::Type)f ) != d->s8 )
        f++;
    if ( f <= HeaderField::LastAddressField )
        return whereAddressField( d->s8 );

    root()->d->needHeaderFields = true;

    uint fnum = placeHolder();
    root()->d->query->bind( fnum, d->s8 );
    if ( d->s16.isEmpty() )
        return
            "hf.field=(select id from field_names where name=$" +
            fn( fnum ) + ")";
            
    uint like = placeHolder();
    root()->d->query->bind( like, q( d->s16 ) );
    return
        "(hf.value ilike " + matchAny( like ) + " and "
        "hf.field=(select id from field_names where name=$" + fn( fnum ) + "))";
}


/*! This implements searches on the single address field \a field, or
    on all address fields if \a field is empty.
*/

String Selector::whereAddressField( const String & field )
{
    StringList l;
    if ( !field.isEmpty() )
        l.append( field );
    return whereAddressFields( l, d->s16 );
}


/*! This implements searching for \a name on the address \a fields, or
    on all address fields if \a fields is the empty list.
*/

String Selector::whereAddressFields( const StringList & fields,
                                     const UString & name )
{
    root()->d->needAddresses = true;
    root()->d->needAddressFields = true;
    Query * query = root()->d->query;

    String r( "(" );
    String s;
    if ( fields.isEmpty() ) {
        // any address field.
    }
    else {
        r.append( "af.field in (select id from field_names fn where (" );
        bool first = true;
        StringList::Iterator it( fields );
        while ( it ) {
            uint fnum = placeHolder();
            query->bind( fnum, *it );
            if ( !first )
                r.append( " or " );
            r.append( "fn.name=$" + fn( fnum ) );
            first = false;
            ++it;
        }
        r.append( "))" );
        s = " and ";
    }

    String raw( q( name ) );
    int at = raw.find( '@' );

    if ( at < 0 ) {
        uint name = placeHolder();
        query->bind( name, raw );
        r.append( s );
        r.append( "(a.name ilike " + matchAny( name ) + " or"
                  " a.localpart ilike " + matchAny( name ) + " or"
                  " a.domain ilike " + matchAny( name ) + ")" );
    }
    else {
        String lc, dc;
        if ( at > 0 ) {
            uint lp = placeHolder();
            if ( raw.startsWith( "<" ) ) {
                query->bind( lp, raw.mid( 1, at-1 ) );
                lc = "a.localpart ilike $" + fn( lp );
            }
            else {
                query->bind( lp, raw.mid( 0, at ) );
                lc = "a.localpart ilike '%'||$" + fn( lp ) + " ";
            }
        }
        if ( at < (int)raw.length() - 1 ) {
            uint dom = placeHolder();
            if ( raw.endsWith( ">" ) ) {
                query->bind( dom, raw.mid( at+1, raw.length()-at-2 ) );
                dc = "a.domain ilike $" + fn( dom );
            }
            else {
                query->bind( dom, raw.mid( at+1 ) );
                dc = "a.domain ilike $" + fn( dom ) + "||'%'";
            }
        }
        if ( lc.isEmpty() && dc.isEmpty() ) {
            // imap SEARCH FROM "@" matches messages with a nonempty
            // from field. the sort of thing only a test suite would
            // do.
        }
        if ( !lc.isEmpty() ) {
            r.append( s );
            r.append( lc );
        }
        if ( !dc.isEmpty() ) {
            r.append( s );
            r.append( dc );
        }
    }
    r.append( ")" );
    return r;
}


/*! This implements searches on all header fields.
*/

String Selector::whereHeader()
{
    root()->d->needHeaderFields = true;

    uint str = placeHolder();
    root()->d->query->bind( str, q( d->s16 ) );
    return
        "(" + whereAddressField() + " or "
        "hf.value ilike " + matchAny( str ) + ")";
}


/*! This implements searches on (text) bodyparts. We cannot and will
    not do "full-text" search on the contents of e.g. jpeg
    pictures. (For some formats we search on the text part, because
    the injector sets bodyparts.text based on bodyparts.data.)
*/

String Selector::whereBody()
{
    root()->d->needBodyparts = true;

    String s;

    uint bt = placeHolder();
    root()->d->query->bind( bt, q( d->s16 ) );

    String db = Database::type();
    if ( db.lower().endsWith( "tsearch2" ) )
        s.append( "bp.ftidx @@ to_tsquery('default', $" + fn( bt ) + ")" );
    else
        s.append( "bp.text ilike " + matchAny( bt ) );

    return s;
}


/*! This implements searches on the rfc822size of messages.
*/

String Selector::whereRfc822Size()
{
    uint s = placeHolder();
    root()->d->query->bind( s, d->n );
    if ( d->a == Smaller )
        return "messages.rfc822size<$" + fn( s );
    else if ( d->a == Larger )
        return "messages.rfc822size>$" + fn( s );
    setError( "Internal error: " + debugString() );
    return "";
}


/*! This implements searches on whether a message has/does not have
    flags.
*/

String Selector::whereFlags()
{
    if ( d->s8 == "\\recent" ) {
        // the database cannot look at the recent flag, so we turn
        // this query into a test for the relevant UIDs.
        String r;
        if ( root()->d->session )
            r = root()->d->session->recent().where( "m" );
        // where() returns an empty string if recent() is an empty set
        if ( r.isEmpty() )
            return "false";
        return r;
    }

    Flag * f = Flag::find( d->s8 );
    if ( !f ) {
        // if we don't know about this flag, it doesn't exist in this
        // session and is never set, as far as this client is concerned.
        return "false";
    }

    root()->d->needFlags.add( f->id() );
    return "f" + fn( f->id() ) + ".flag is not null";
}


/*! This implements searches on whether a message has the right UID.
*/

String Selector::whereUid()
{
    if ( d->s.isEmpty() )
        return "false";

    if ( !d->s.isRange() )
        return "(" + d->s.where( "m" ) + ")";

    // if we can, use a placeholder, so we can prepare a statement (we
    // don't at the moment, but it'll help).
    if ( d->s.count() == 1 ) {
        uint value = placeHolder();
        root()->d->query->bind( value, d->s.value( 1 ) );
        return "m.uid=$" + fn( value );
    }

    uint min = d->s.value( 1 );
    uint max = d->s.largest();
    uint minp = placeHolder();
    root()->d->query->bind( minp, min );
    if ( max == UINT_MAX )
        return "m.uid>=$" + fn( minp );
    uint maxp = placeHolder();
    root()->d->query->bind( maxp, max );
    return "(m.uid>=$" + fn( minp ) + " and m.uid<=$" + fn( maxp ) + ")";
}


/*! This implements searches on whether a message has/does not have
    the right annotation.
*/

String Selector::whereAnnotation()
{
    root()->d->needAnnotations = true;
    ::AnnotationName * a = ::AnnotationName::find( d->s8 );
    String annotations;
    if ( a ) {
        annotations = "a.name=" + fn( a->id() );
    }
    else {
        uint n = 0;
        uint u = 0;
        while ( u <= ::AnnotationName::largestId() ) {
            a = ::AnnotationName::find( u );
            u++;
            if ( a && lmatch( d->s8, 0, a->name(), 0 ) == 2 ) {
                n++;
                if ( !annotations.isEmpty() )
                    annotations.append( " or " );
                annotations.append( "a.name=" );
                annotations.append( fn( a->id() ) );
            }
        }
        if ( n > 1 )
            annotations = "(" + annotations + ")";
        if ( ( n < 1 || n > 3 ) && d->s8.find( '%' ) < 0 ) {
            // if we don't know the desired annotation or there seems
            // to be many possibles, we're better off using set logic.
            uint pattern = placeHolder();
            annotations = "a.name in ("
                          "select id from annotation_names where name like $" +
                          fn( pattern ) +
                          ")";
            String sql = 0;
            uint i = 0;
            while ( i < d->s8.length() ) {
                if ( d->s8[i] == '*' )
                    sql.append( '%' );
                else
                    sql.append( d->s8[i] );
                i++;
            }
            root()->d->query->bind( pattern, sql );
        }
        // this still leaves a bad case - e.g. if the client searches
        // for '/vendor/microsoft/%' and we don't have any suitable
        // annotation names in RAM.
    }

    String user;
    String attribute;
    if ( d->s8b.endsWith( ".priv" ) ) {
        attribute = d->s8b.mid( 0, d->s8b.length()-5 ).lower();
        uint userId = placeHolder();
        user = "a.owner=$" + fn( userId );
        root()->d->query->bind( userId, root()->d->user->id() );
    }
    else if ( d->s8b.endsWith( ".shared" ) ) {
        attribute = d->s8b.mid( 0, d->s8b.length()-7 ).lower();
        user = "a.owner is null";
    }
    else {
        attribute = d->s8b.lower();
        uint userId = placeHolder();
        user = "(a.owner is null or a.owner=$" + fn( userId ) + ")";
        root()->d->query->bind( userId, root()->d->user->id() );
    }

    String like = "is not null";
    if ( !d->s16.isEmpty() ) {
        uint i = placeHolder();
        root()->d->query->bind( i, q( d->s16 ) );
        like = "ilike " + matchAny( i );
    }

    return "(" + user + " and " + annotations + " and value " + like + ")";
}


/*! This implements any search that's not bound to a specific field,
    generally booleans and "all".

    As a hack, oops, as an optimization, this function also looks for
    an OR list of address-field searches, and if any, lifts the shared
    parts of those seaches out so the DBMS processes the search
    faster.
*/

String Selector::whereNoField()
{
    if ( d->a == And || d->a == Or ) {
        if ( d->children->isEmpty() ) {
            if ( d->a == And )
                return "true";
            return "false";
        }
        StringList conditions;
        UString address;
        StringList addressFields;
        if ( d->a == Or ) {
            List<Selector>::Iterator i( d->children );
            while ( i && ( i->d->f != Header || i->d->s8.isEmpty() ) )
                i++;
            if ( i )
                address = i->d->s16; // this is the address we optimze for
        }
        List<Selector>::Iterator i( d->children );
        while ( i ) {
            bool af = false;
            if ( d->a == Or &&
                 i->d->f == Header &&
                 !address.isEmpty() &&
                 !i->d->s8.isEmpty() &&
                 address == i->d->s16 ) {
                uint t = HeaderField::fieldType( i->d->s8 );
                if ( t > 0 && t <= HeaderField::LastAddressField )
                    af = true;
            }
            if ( af )
                addressFields.append( i->d->s8.headerCased() );
            else
                conditions.append( i->where() );
            i++;
        }
        if ( !addressFields.isEmpty() )
            conditions.append( whereAddressFields( addressFields, address ) );
        String r = "(";
        if ( d->a == And )
            r.append( conditions.join( " and " ) );
        else
            r.append( conditions.join( " or " ) );
        r.append( ")" );
        return r;
    }
    else if ( d->a == Not ) {
        return "not " + d->children->first()->where() + "";
    }
    else if ( d->a == All ) {
        return "true";
    }
    else if ( d->a == None ) {
        return "false";
    }
    setError( "Internal error: " + debugString() );
    return "";
}


/*! Give an ASCII representatation of this object, suitable for debug
    output or for equality testing.
*/

String Selector::debugString() const
{
    String r;

    String o, w;

    switch ( d->a ) {
    case OnDate:
        o = "on";
        break;
    case SinceDate:
        o = "since";
        break;
    case BeforeDate:
        o = "before";
        break;
    case Contains:
        o = "contains";
        break;
    case Larger:
        o = "larger";
        break;
    case Smaller:
        o = "smaller";
        break;
    case And:
    case Or:
        break;
    case Not:
        return "not " + d->children->first()->debugString();
    case All:
        return "all";
        break;
    case None:
        return "none";
        break;
    };

    if ( o.isEmpty() ) {
        r = "(";
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            r += i->debugString();
            ++i;
            if ( i ) {
                if ( d->a == And )
                    r += " and ";
                else
                    r += " or ";
            }
        }
        r += ")";
        return r;
    }

    switch( d->f ) {
    case InternalDate:
        w = "delivery";
        break;
    case Sent:
        w = "sent";
        break;
    case Header:
        if ( d->s8.isEmpty() )
            w = "header";
        else
            w = "header field " + d->s8;
        break;
    case Body:
        w = "body";
        break;
    case Rfc822Size:
        w = "rfc822 size";
        break;
    case Flags:
        w = "set of flags";
        break;
    case NoField:
        w = "none";
        break;
    case Uid:
        return d->s.where();
        break;
    case Annotation:
        w = "annotation " + d->s8b + " of ";
    };

    r = w + " " + o + " ";
    if ( d->s16.isEmpty() )
        r.append( d->s8 );
    else
        r.append( d->s16.ascii() );

    return r;

}


/*! Matches the message with the given \a uid in the session \a s
    against this condition, provided the match is reasonably simple and
    quick, and returns either Yes, No, or (if the match is difficult,
    expensive or depends on data that isn't available) Punt.
*/

Selector::MatchResult Selector::match( Session * s, uint uid )
{
    if ( d->a == And || d->a == Or ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            MatchResult sub = i->match( s, uid );
            if ( sub == Punt )
                return Punt;
            if ( d->a == And && sub == No )
                return No;
            if ( d->a == Or && sub == Yes )
                return Yes;
            ++i;
        }
        if ( d->a == And )
            return Yes;
        else
            return No;
    }
    else if ( d->a == Contains && d->f == Uid ) {
        if ( d->s.contains( uid ) )
            return Yes;
        return No;
    }
    else if ( d->a == Contains && d->f == Flags ) {
        if ( d->s8 == "\\recent" ) {
            if ( s->isRecent( uid ) )
                return Yes;
            return No;
        }
        return Punt;
    }
    else if ( d->a == Not ) {
        MatchResult sub = d->children->first()->match( s, uid );
        if ( sub == Punt )
            return Punt;
        else if ( sub == Yes )
            return No;
        else
            return Yes;
    }
    else if ( d->a == All ) {
        return Yes;
    }

    return Punt;
}


/*! Returns true if this condition needs an updated Session to be
    correctly evaluated, and false if not.
*/

bool Selector::needSession() const
{
    if ( d->a == Contains && d->f == Flags && d->s8 == "\\recent" )
        return true;

    if ( d->a == And || d->a == Or ) {
        List< Selector >::Iterator i( d->children );
        while ( i ) {
            if ( i->needSession() )
                return true;
            ++i;
        }
    }
    return false;
}


static uint lmatch( const String & pattern, uint p,
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
                uint s = lmatch( pattern, p, name, i );
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


/*! Returns a string representing the number (without $) of the
    placeholder that's bound to the mbox id.
*/

String Selector::mboxId()
{
    return fn( root()->d->mboxId );
}


/*! Returns the string representation of this Selector. This is what's
    stored in the views.selector column in the database. */

String Selector::string()
{
    Utf8Codec u;
    String r( "(" );

    switch ( d->a ) {
    case OnDate:
        if ( d->f == InternalDate )
            r.append( "received" );
        else if ( d->f == Sent )
            r.append( "sent" );
        r.append( "on" );
        r.append( " " );
        r.append( d->s8.quoted() );
        break;
    case SinceDate:
        if ( d->f == InternalDate )
            r.append( "received" );
        else if ( d->f == Sent )
            r.append( "sent" );
        r.append( "since" );
        r.append( " " );
        r.append( d->s8.quoted() );
        break;
    case BeforeDate:
        if ( d->f == InternalDate )
            r.append( "received" );
        else if ( d->f == Sent )
            r.append( "sent" );
        r.append( "before" );
        r.append( " " );
        r.append( d->s8.quoted() );
        break;
    case Contains:
        if ( d->f == Header ) {
            r.append( "header" );
            r.append( " " );
            r.append( d->s8.quoted() );
            r.append( " " );
            r.append( u.fromUnicode( d->s16 ).quoted() );
        }
        else if ( d->f == Body ) {
            r.append( "body" );
            r.append( " " );
            r.append( u.fromUnicode( d->s16 ).quoted() );
        }
        else if ( d->f == Flags ) {
            r.append( "flag" );
            r.append( " " );
            r.append( d->s8.quoted() );
        }
        else if ( d->f == Uid ) {
            r.append( "messageset" );
            r.append( " " );
            r.append( d->s.set().quoted() );
        }
        else if ( d->f == Annotation ) {
            r.append( "annotation" );
            r.append( " " );
            r.append( d->s8.quoted() );
            r.append( " " );
            r.append( d->s8b.quoted() );
            r.append( " " );
            r.append( u.fromUnicode( d->s16 ).quoted() );
        }
        break;
    case Larger:
        r.append( "messagelarger" );
        r.append( " " );
        r.append( fn( d->n ) );
        break;
    case Smaller:
        r.append( "messagesmaller" );
        r.append( " " );
        r.append( fn( d->n ) );
        break;
    case And:
        r.append( "and" );
        break;
    case Or:
        r.append( "or" );
        break;
    case Not:
        r.append( "not" );
        break;
    case All:
        r.append( "true" );
        break;
    case None:
        r.append( "false" );
        break;
    }

    List< Selector >::Iterator it( d->children );
    while ( it ) {
        r.append( " " );
        r.append( it->string() );
        ++it;
    }

    r.append( ")" );
    return r;
}


/*! Returns the first error recorded with setError, or an empty string
    if none has been recorded yet.
*/

String Selector::error()
{
    return root()->d->error;
}


/*! This static function takes a canonical string representation \a s,
    and returns the Selector corresponding to it, or 0 if there was a
    parsing error.
*/

Selector * Selector::fromString( const String &s )
{
    Selector * r = new Selector;

    uint i = 0;

    if ( s[i++] != '(' )
        return 0;

    String op;
    while ( s[i] <= 'z' && s[i] >= 'a' )
        op.append( s[i++] );

    if ( op == "and" || op == "or" || op == "not" ) {
        if ( op == "and" )
            r->d->a = And;
        else if ( op == "or" )
            r->d->a = Or;
        else if ( op == "not" )
            r->d->a = Not;

        while ( s[i] == ' ' ) {
            i++;

            uint j = i;
            if ( s[i++] != '(' )
                return 0;

            int parenLevel = 1;
            while ( parenLevel > 0 && i < s.length() ) {
                if ( s[i] == '"' ) {
                    i++;
                    while ( s[i] != '"' && i < s.length() ) {
                        if ( s[i] == '\\' )
                            i++;
                        i++;
                    }
                    if ( s[i] != '"' )
                        return 0;
                }
                else if ( s[i] == '(' ) {
                    parenLevel++;
                }
                else if ( s[i] == ')' ) {
                    parenLevel--;
                }
                i++;
            }
            if ( parenLevel != 0 )
                return 0;

            Selector * child = fromString( s.mid( j, i-j ) );
            if ( !child )
                return 0;
            child->d->parent = r;
            r->d->children->append( child );
        }

        if ( r->d->children->isEmpty() ||
             ( op == "not" && r->d->children->count() != 1 ) )
            return 0;
    }
    else if ( op == "receivedon" || op == "senton" ||
              op == "receivedsince" || op == "sentsince" ||
              op == "receivedbefore" || op == "sentbefore" )
    {
        if ( op.endsWith( "on" ) )
            r->d->a = OnDate;
        else if ( op.endsWith( "since" ) )
            r->d->a = SinceDate;
        else
            r->d->a = BeforeDate;

        if ( op.startsWith( "received" ) )
            r->d->f = InternalDate;
        else
            r->d->f = Sent;

        if ( s[i++] != ' ' )
            return 0;

        uint j = i;
        if ( s[i++] != '"' )
            return 0;
        while ( s[i] != '"' && i < s.length() ) {
            if ( s[i] == '\\' )
                i++;
            i++;
        }
        if ( s[i++] != '"' )
            return 0;

        r->d->s8 = s.mid( j, i-j ).unquoted();
    }
    else if ( op == "header" || op == "body" || op == "flag" ||
              op == "messageset" || op == "annotation" )
    {
        r->d->a = Contains;

        if ( op == "header" )
            r->d->f = Header;
        else if ( op == "body" )
            r->d->f = Body;
        else if ( op == "flag" )
            r->d->f = Flags;
        else if ( op == "messageset" )
            r->d->f = Uid;
        else if ( op == "annotation" )
            r->d->f = Annotation;

        if ( r->d->f != Body ) {
            if ( s[i++] != ' ' )
                return 0;

            uint j = i;
            if ( s[i++] != '"' )
                return 0;
            while ( s[i] != '"' && i < s.length() ) {
                if ( s[i] == '\\' )
                    i++;
                i++;
            }
            if ( s[i++] != '"' )
                return 0;

            String t = s.mid( j, i-j ).unquoted();

            if ( r->d->f == Uid ) {
                StringList * l = StringList::split( ',', t );
                StringList::Iterator it( l );
                while ( it ) {
                    StringList * range = StringList::split( ':', *it );
                    r->d->s.add( range->first()->number( 0 ),
                                 range->last()->number( 0 ) );
                    ++it;
                }
            }
            else {
                r->d->s8 = t;
            }
        }

        if ( r->d->f == Annotation ) {
            if ( s[i++] != ' ' )
                return 0;

            uint j = i;
            if ( s[i++] != '"' )
                return 0;
            while ( s[i] != '"' && i < s.length() ) {
                if ( s[i] == '\\' )
                    i++;
                i++;
            }
            if ( s[i++] != '"' )
                return 0;

            r->d->s8b = s.mid( j, i-j ).unquoted();
        }

        if ( r->d->f == Header || r->d->f == Body ||
             r->d->f == Annotation )
        {
            if ( s[i++] != ' ' )
                return 0;

            uint j = i;
            if ( s[i++] != '"' )
                return 0;
            while ( s[i] != '"' && i < s.length() ) {
                if ( s[i] == '\\' )
                    i++;
                i++;
            }
            if ( s[i++] != '"' )
                return 0;

            Utf8Codec u;
            r->d->s16 = u.toUnicode( s.mid( j, i-j ).unquoted() );
            if ( !u.valid() )
                return 0;
        }
    }
    else if ( op == "messagelarger" || op == "messagesmaller" ) {
        if ( op.endsWith( "larger" ) )
            r->d->a = Larger;
        else
            r->d->a = Smaller;

        if ( s[i++] != ' ' )
            return 0;

        uint j = i;
        if ( s[i] <= '9' && s[i] >= '1' )
            i++;
        else
            return 0;
        while ( s[i] <= '9' && s[i] >= '0' )
            i++;

        bool ok;
        r->d->n = s.mid( j, i-j ).number( &ok );
        if ( !ok )
            return 0;
    }
    else if ( op == "true" ) {
        r->d->a = All;
    }
    else if ( op == "false" ) {
        r->d->a = None;
    }
    else {
        return 0;
    }

    if ( s[i++] != ')' || i < s.length() )
        return 0;

    return r;
}
