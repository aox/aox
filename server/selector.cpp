// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "selector.h"

#include "map.h"
#include "utf.h"
#include "dict.h"
#include "flag.h"
#include "date.h"
#include "cache.h"
#include "session.h"
#include "mailbox.h"
#include "allocator.h"
#include "estringlist.h"
#include "configuration.h"
#include "transaction.h"
#include "annotation.h"
#include "dbsignal.h"
#include "field.h"
#include "user.h"

#include <time.h> // whereAge() calls time()


static bool tsearchAvailable = false;
static bool retunerCreated = false;

static EString * tsconfig;


class TuningDetector
    : public EventHandler
{
public:
    TuningDetector(): q( 0 ) {
        ::tsearchAvailable = false;
        q = new Query(
            "select indexdef from pg_indexes where "
            "indexdef ilike '% USING gin (to_tsvector%'"
            "and tablename='bodyparts' and schemaname=$1",
            this
        );
        q->bind( 1, Configuration::text( Configuration::DbSchema ) );
        q->execute();
    }
    void execute() {
        if ( !q->done() )
            return;
        ::tsearchAvailable = q->hasResults();
        Row * r = q->nextRow();
        if ( r ) {
            EString def( r->getEString( "indexdef" ) );

            uint n = 12 + def.find( "to_tsvector(" );
            def = def.mid( n, def.length()-n-1 ).section( ",", 1 );

            if ( def[0] == '\'' && def.endsWith( "::regconfig" ) ) {
                tsconfig = new EString( def );
                Allocator::addEternal( tsconfig, "tsearch configuration" );
            }
            else {
                ::tsearchAvailable = false;
            }
        }
    }
    Query * q;
};


class RetuningDetector
    : public EventHandler
{
public:
    RetuningDetector(): EventHandler() {
        ::retunerCreated = true;
        setLog( new Log );
        (void)new DatabaseSignal( "database_retuned", this );
        (void)new TuningDetector();
    }
    void execute() {
        (void)new TuningDetector();
    }
};


static uint lmatch( const EString &, uint, const EString &, uint );


class SelectorData
    : public Garbage
{
public:
    SelectorData()
        : f( Selector::NoField ), a( Selector::None ),
          n( 0 ), m( 0 ), mc( 0 ),
          placeholder( 0 ), join( 0 ), query( 0 ), parent( 0 ),
          children( new List< Selector > ), msg( 0 ), mm( 0 ),
          session( 0 ),
          needDateFields( false ),
          needAnnotations( false ),
          needBodyparts( false ),
          needMessages( false )
    {}

    void copy( SelectorData * o ) {
        f = o->f;
        a = o->a;
        s8 = o->s8;
        s8b = o->s8b;
        s16 = o->s16;
        s = o->s;
        n = o->n;
        m = o->m;
        mc = o->mc;
        children = o->children;
    }

    Selector::Field f;
    Selector::Action a;

    EString error;

    EString s8;
    EString s8b;
    UString s16;
    IntegerSet s;
    uint n;
    Mailbox * m;
    bool mc;

    Dict<uint> estringPlaceholders;
    UDict<uint> ustringPlaceholders;

    int placeholder;
    int join;
    Query * query;

    Selector * parent;
    List< Selector > * children;
    EString * msg;
    EString * mm;
    Session * session;
    User * user;

    EStringList extraJoins;
    EStringList leftJoins;

    bool needDateFields;
    bool needAnnotations;
    bool needBodyparts;
    bool needMessages;
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


/*! Constructs an empty selector with field \a f and Action Special. */

Selector::Selector( Field f )
    : d( new SelectorData )
{
    d->f = f;
    d->a = Special;
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

Selector::Selector( Field f, Action a, const EString &s )
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


/*! Creates a selector with Field \a f, Action \a a, the EString value
    \a s, and the UString value \a u.
*/

Selector::Selector( Field f, Action a, const EString &s, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s16 = u;
}


/*! Creates a selector with Field \a f, Action \a a, the EString values
    \a s and \a t, and the UString value \a u.
*/

Selector::Selector( Field f, Action a, const EString &s,
                    const EString &t, const UString &u )
    : d( new SelectorData )
{
    d->f = f;
    d->a = a;
    d->s8 = s;
    d->s8b = t;
    d->s16 = u;
}


/*! Creates a selector from the IntegerSet \a s. */

Selector::Selector( const IntegerSet &s )
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


/*! Constructs a selector that matches messages in \a mailbox and if
    \a alsoChildren is true, also in its children.
*/

Selector::Selector( Mailbox * mailbox, bool alsoChildren )
    : d( new SelectorData )
{
    d->a = Special;
    d->f = MailboxTree;
    d->m = mailbox;
    d->mc = alsoChildren;
}


/*! Returns the ultimate parent of this Selector. */

Selector * Selector::root()
{
    Selector * p = this;

    while ( p->parent() )
        p = p->parent();

    return p;
}


/*! Returns the parent of this Selector, or 0 if it is the root. */

Selector * Selector::parent()
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


/*! Returns a placeholder bound to \a s, creating one if necessary. */

uint Selector::placeHolder( const EString & s )
{
    uint * x = root()->d->estringPlaceholders.find( s );
    if ( !x ) {
        x = (uint*)Allocator::alloc( sizeof( uint ) );
        * x = placeHolder();
        root()->d->estringPlaceholders.insert( s, x );
        root()->d->query->bind( *x, s );
    }
    return *x;
}


/*! Returns a placeholder bound to \a s, creating one if necessary. */

uint Selector::placeHolder( const UString & s )
{
    uint * x = root()->d->ustringPlaceholders.find( s );
    if ( !x ) {
        x = (uint*)Allocator::alloc( sizeof( uint ) );
        * x = placeHolder();
        root()->d->ustringPlaceholders.insert( s, x );
        root()->d->query->bind( *x, s );
    }
    return *x;
}


/*! Records \a s as an error during the construction of this Selector
    tree. Only the first error in a tree is recorded, and it is recorded
    at the root of the tree (rather than the node where it occurred).
*/

void Selector::setError( const EString &s )
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
        Selector * child = d->children->first()->d->children->first();
        d->copy( child->d );
    }

    if ( d->a == Larger ) {
        if ( d->n == 0 || // > 0 matches everything
             ( d->n == 1 && d->f == Modseq ) ) // all messages have modseq >= 1
            d->a = All;
    }
    else if ( d->a == Contains && d->f == Uid ) {
        if ( d->s.isEmpty() )
            d->a = None; // contains d->a set of nonexistent messages
    }
    else if ( d->a == Contains ) {
        // x contains y may match everything
        switch ( d->f ) {
        case InternalDate:
        case Sent:
            d->a = None;
            break;
        case Header:
            if ( d->s16.isEmpty() && d->s8.isEmpty() )
                d->a = All;
            break;
        case Body:
            if ( d->s16.isEmpty() )
                d->a = All;
            break;
        case Rfc822Size:
            break;
        case Flags:
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
        case Modseq:
            // contains modseq shouldn't happen, and certainly cannot
            // be simplified
            break;
        case Age:
            // cannot be simplified, should not happen
            break;
        case MailboxTree:
            // cannot be simplified
            break;
        case InThread:
            // cannot be simplified
            break;
        case DatabaseId:
            // cannot be simplified
            break;
        case ThreadId:
            // cannot be simplified
            break;
        case NoField:
            // contains is orthogonal to nofield, so this we cannot
            // simplify
            break;
        }
        // contains empty string too
    }
    else if ( d->a == Equals &&
              d->n == 0 &&
              ( d->f == ThreadId || d->f == DatabaseId ) ) {
        d->a = None;
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
        d->copy( d->children->first()->d );
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
    results.

    The \a mailbox to search is passed in separately, because we can't
    use the Session's mailbox while building views. If \a mailbox is a
    null pointer, the query will search either the entire database or
    the part that's visible to \a user.

    If \a deleted is supplied and true (the default is false), then
    the Query looks at the deleted_messages table instead of the
    mailbox_messages one.

    The search results will be ordered if \a order is true (this is
    the default). The order is ascending and uses whatever is
    specified in \a wanted of mailbox, thread_root, uid, message and idate.

    Each Query Row will have the result columns named in \a wanted, or
    "uid", "modseq" and "message" if \a wanted is left at the default
    value.

*/

Query * Selector::query( User * user, Mailbox * mailbox,
                         Session * session, EventHandler * owner,
                         bool order, EStringList * wanted, bool deleted )
{
    if ( !::retunerCreated && Database::numHandles() )
        (void)new RetuningDetector;

    d->query = new Query( owner );
    d->user = user;
    d->session = session;
    d->placeholder = 0;
    d->estringPlaceholders.clear();
    d->ustringPlaceholders.clear();
    uint mboxId = 0;
    if ( mailbox ) {
        mboxId = placeHolder();
        d->query->bind( mboxId, mailbox->id() );
    }
    if ( deleted )
        d->mm = new EString( "dm" );
    else
        d->mm = new EString( "mm" );
    EString q = "select ";
    if ( wanted ) {
        EStringList::Iterator i( wanted );
        while ( i ) {
            if ( i->contains( "." ) )
                q.append( *i );
            else
                q.append( mm() + "." + *i );
            ++i;
            if ( i )
                q.append( ", " );
        }
    }
    else {
        q.append( mm() + ".uid, " + mm() + ".modseq, " + mm() + ".message" );
    }

    if ( deleted )
        q.append( " from deleted_messages " + mm() );
    else
        q.append( " from mailbox_messages " + mm() );
    EString w = where();
    if ( d->a == And && w.startsWith( "(" ) && w.endsWith( ")" ) )
        w = w.mid( 1, w.length() - 2 );

    if ( wanted && wanted->contains( "m.idate" ) )
        d->needMessages = true;

    if ( d->needDateFields )
        q.append( " join date_fields df on "
                  "(df.message=" + mm() + ".message)" );
    if ( d->needAnnotations )
        q.append( " join annotations a on (" + mm() + ".mailbox=a.mailbox"
                  " and " + mm() + ".uid=a.uid)" );
    if ( d->needBodyparts )
        q.append( " join part_numbers pn on (pn.message=" + mm() + ".message)"
                  " join bodyparts bp on (bp.id=pn.bodypart)" );
    if ( d->needMessages )
        q.append( " join messages m on (" + mm() + ".message=m.id)" );

    q.append( d->extraJoins.join( "" ) );
    q.append( d->leftJoins.join( "" ) );

    EString mboxClause;
    if ( mboxId ) {
        // normal case: search one mailbox
        mboxClause = mm() + ".mailbox=$" + fn( mboxId );
    }
    else if ( user ) {
        // search all mailboxes accessible to user
        uint owner = placeHolder();
        d->query->bind( owner, user->id() );
        q.append( " join mailboxes mb on (" + mm() + ".mailbox=mb.id)" );
        uint n = placeHolder( user->login() );
        mboxClause =
            // I think this one needs commentary.
            "exists "
            // this subselect returns true if either anyone or the named user
            // has the r right for subsubmailbox...
            "(select rights "
            " from permissions"
            " where (identifier='anyone' or identifier=$"+fn(n)+") and"
            "  rights='%r%' and"
            "  mailbox=("
            // this selects the mailbox whose permissions rows
            // applies. that's either the mailbox itself, or the
            // closest parent which has a permissions row.
            "   select mp.id"
            "    from mailboxes mp"
            "    join permssions p on (mp.id=p.mailbox)"
            "    where (p.identifier='anyone' or p.identifier=$"+fn(n)+") and"
            "    (mp.id=mb.id or"
            "     lower(mp.name)||'/'="
            "     lower(substring(mb.name from 1 for length(mp.name)+1)))"
            // use the mailbox which has permissions rows and has the
            // longest name.
            "    order by length(mp.name) desc limit 1))";
    }
    else {
        // search all mailboxes, optionally limited by mailbox
        // selectors in the tree.
    }

    if ( mboxClause.isEmpty() && w == "true" ) {
        // no mailbox, no condition. this will result in a large
        // result set. can it be correct?
    }
    else if ( mboxClause.isEmpty() ) {
        // a condition that applies to all mailboxes
        q.append( " where " );
        q.append( w );
    }
    else if ( w == "true" ) {
        // a mailbox clause, but no condition
        q.append( " where " );
        q.append( mboxClause.simplified() );
    }
    else {
        // both.
        q.append( " where " );
        q.append( mboxClause.simplified() );
        q.append( " and " );
        q.append( w );
    }

    if ( order ) {
        if ( wanted->contains( "uid" ) && wanted->contains( "mailbox" ) )
            q.append( " order by " + mm() + ".mailbox, " + mm() + ".uid" );
        else if ( wanted->contains( "uid" ) || !wanted )
            q.append( " order by " + mm() + ".uid" );
        else if ( wanted->contains( "message" ) )
            q.append( " order by " + mm() + ".message" );
        else if ( wanted->contains( "m.idate" ) )
            q.append( " order by m.idate" );
    }

    d->query->setString( q );
    return d->query;
}


/*! Gives an SQL string representing this condition.

    The string may include $n placeholders; where() and its helpers
    will bind them as required.
*/

EString Selector::where()
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
    case Modseq:
        return whereModseq();
        break;
    case Age:
        return whereAge();
        break;
    case MailboxTree:
        return whereMailbox();
        break;
    case InThread:
        return whereInThread();
        break;
    case NoField:
        return whereNoField();
        break;
    case DatabaseId:
        return whereDatabaseId();
        break;
    case ThreadId:
        return whereThreadId();
        break;
    }
    setError( "Internal error for " + debugString() );
    return "";
}

/*! This implements the INTERNALDATE part of where().
*/

EString Selector::whereInternalDate()
{
    root()->d->needMessages = true;

    uint day = d->s8.mid( 0, 2 ).number( 0 );
    EString month = d->s8.mid( 3, 3 );
    uint year = d->s8.mid( 7 ).number( 0 );
    // XXX: local time zone is ignored here
    Date d1;
    d1.setDate( year, month, day, 0, 0, 0, 0 );
    Date d2;
    d2.setDate( year, month, day, 23, 59, 59, 0 );

    if ( d->a == OnDate ) {
        uint n1 = placeHolder();
        root()->d->query->bind( n1, d1.unixTime() );
        uint n2 = placeHolder();
        root()->d->query->bind( n2, d2.unixTime() );
        return "(" + m() + ".idate>=$" + fn( n1 ) +
            " and " + m() + ".idate<=$" + fn( n2 ) + ")";
    }
    else if ( d->a == SinceDate ) {
        uint n1 = placeHolder();
        root()->d->query->bind( n1, d1.unixTime() );
        return m() +".idate>=$" + fn( n1 );
    }
    else if ( d->a == BeforeDate ) {
        uint n2 = placeHolder();
        root()->d->query->bind( n2, d2.unixTime() );
        return m() + ".idate<=$" + fn( n2 );
    }

    setError( "Cannot search for: " + debugString() );
    return "";
}


/*! This implements the SENTON/SENTBEFORE/SENTSINCE part of where().
*/

EString Selector::whereSent()
{
    root()->d->needDateFields = true;

    uint day = d->s8.mid( 0, 2 ).number( 0 );
    EString month = d->s8.mid( 3, 3 );
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


static EString matchAny( int n )
{
    return "'%'||$" + fn( n ) + "||'%'";
}


static EString q( const UString & orig )
{
    Utf8Codec c;
    EString r( c.fromUnicode( orig ) );

    EString s;
    uint i = 0;
    while ( i < r.length() ) {
        if ( r[i] == '\\' || r[i] == '_' || r[i] == '%' )
            s.append( '\\' );
        s.append( r[i] );
        i++;
    }

    return s;
}


static EString matchTsvector( const EString & col, uint n )
{
    EString s( "octet_length(" );
    s.append( col );
    s.append( ")<640000 and to_tsvector(" );
    s.append( *tsconfig );
    s.append( ", " );
    s.append( col );
    s.append( ") @@ plainto_tsquery($" );
    s.appendNumber( n );
    s.append( ")" );
    return s;
}


static bool sensibleWords( const UString & s )
{
    uint l = 0;
    uint i = 0;
    while ( i < s.length() ) {
        uint c = s[i];
        if ( UString::isLetter( c ) )
            l++;
        else if ( UString::isDigit( c ) || UString::isSpace( c ) )
            ; // no action, but ok
        else
            return false;
        ++i;
    }
    if ( l > 0 )
        return true;
    return false;
}


/*! This implements searches on a single header field.
*/

EString Selector::whereHeaderField()
{
    d->s8 = d->s8.headerCased();

    uint f = 1;
    while ( f <= HeaderField::LastAddressField &&
            HeaderField::fieldName( (HeaderField::Type)f ) != d->s8 )
        f++;
    if ( f <= HeaderField::LastAddressField )
        return whereAddressField();

    uint t = HeaderField::fieldType( d->s8 );
    if ( t == HeaderField::Other )
        t = 0;

    EString jn = fn( ++root()->d->join );
    EString j = " left join header_fields hf" + jn +
               " on (" + mm() + ".message=hf" + jn + ".message" +
               " and hf" + jn + ".part=''";

    if ( t == HeaderField::MessageId &&
         d->s16.startsWith( "<" ) && d->s16.endsWith( ">" ) ) {
        uint like = placeHolder( q( d->s16 ) );
        j.append( " and hf" + jn + ".value=$" + fn( like ) );
    }
    else if ( t == HeaderField::Subject &&
              ::tsearchAvailable && sensibleWords( d->s16 ) ) {
        uint like = placeHolder( q( d->s16 ) );
        j.append( " and (" + matchTsvector( "hf" + jn + ".value", like ) + " "
                  "and hf" + jn + ".value ilike " + matchAny( like ) + ")" );
    }
    else if ( !d->s16.isEmpty() ) {
        uint like = placeHolder( q( d->s16 ) );
        j.append( " and hf" + jn + ".value ilike " + matchAny( like ) );
    }

    if ( t ) {
        j.append( " and hf" + jn + ".field=" );
        j.appendNumber( t );
    }
    else {
        uint f = placeHolder( d->s8 );
        j.append( " and hf" + jn + ".field="
                  "(select id from field_names where name=$" + fn(f) + ")" );
    }
    j.append( ")" );
    root()->d->leftJoins.append( j );

    return "hf" + jn + ".field is not null";
}


/*! This helper helps the OR optimiser in whereNoField() to search for
    any of a set of headers or header fields, disregarding address
    fields.

    \a sl must be a non-null pointer to a nonempty list of headers or
    header fields.
*/

EString Selector::whereHeaders( List<Selector> * sl )
{
    if ( sl->count() == 1 )
        return sl->first()->whereHeaderField();

    EStringList likes;
    EStringList fields;
    List<Selector>::Iterator si( sl );
    while ( si ) {
        fields.append( si->d->s8 );
        likes.append( q( si->d->s16 ) );
        ++si;
    }
    fields.removeDuplicates( true );
    likes.removeDuplicates( false );

    EString jn = "hf" + fn( ++root()->d->join );
    EString j = " left join header_fields " + jn +
                " on (" + mm() + ".message=" + jn + ".message" +
                " and " + jn + ".part=''";
    EStringList filters;

    EStringList::Iterator fi( fields );
    while ( fi ) {
        EString fn = fi->headerCased();
        ++fi;

        EString fc;

        if ( fn.isEmpty() ) {
            // we look for all fields
        }
        else {
            uint t = HeaderField::fieldType( fn );
            if ( t == HeaderField::Other ) {
                // we look for an unknown field
                uint f = placeHolder();
                root()->d->query->bind( f, fn );
                fc.append( jn + ".field="
                           "(select id from field_names where name=$" );
                fc.appendNumber( f );
                fc.append( ")" );
            }
            else {
                // we look for one field, and we know what it is
                fc.append( jn + ".field=" );
                fc.appendNumber( t );
            }
        }

        EStringList orl;
        si = sl->first();
        while ( si ) {
            if ( fn == si->d->s8.headerCased() ) {
                if ( fn == "Message-Id" &&
                     si->d->s16.startsWith( "<" ) &&
                     si->d->s16.endsWith( ">" ) ) {
                    uint b = placeHolder( si->d->s16.utf8() );
                    orl.append( jn + ".value=$" + ::fn( b ) );
                }
                else {
                    uint b = placeHolder( q( si->d->s16 ) );
                    orl.append( jn + ".value ilike " + matchAny( b ) );
                }
            }
            ++si;
        }

        bool p = false;
        if ( !fc.isEmpty() ) {
            p = true;
            fc = "(" + fc + " and ";
        }

        if ( orl.count() > 1 )
            fc.append( "(" + orl.join( " or " ) + ")" );
        else
            fc.append( *orl.first() );

        if ( p )
            fc.append( ")" );

        filters.append( fc );
    }

    if ( filters.count() > 1 )
        j.append( " and (" + filters.join( " or " ) + ")" );
    else
        j.append( " and (" + filters.join( "" ) + ")" );
    j.append( ")" );

    root()->d->extraJoins.append( j );
    return jn + ".field is not null";
}


/*! This implements searches on a single address field, or
    on all address fields if stringArgument() is empty.
*/

EString Selector::whereAddressField()
{
    List<Selector> l;
    l.append( this );
    return whereAddressFields( &l );
}


static bool addressPartLegal( const UString & s, bool domain )
{
    if ( s.isEmpty() )
        return false;
    uint i = 0;
    while ( i < s.length() ) {
        uint c = s[i];
        if ( c <= ' ' ) {
            // don't bother searching for domains or localparts
            // containing spaces or control characters.
            return false;
        }
        else if ( c >= 127 ) {
            // ditto DEL or non-ASCII
            return false;
        }
        else if ( ( c >= 'a' && c <= 'z' ) ||
                  ( c >= 'A' && c <= 'Z' ) ||
                  ( c >= '0' && c <= '9' ) ||
                  ( c == '-' ) ) {
            // a-z, A-Z, 0-9 and - are acceptable in both localparts
            // and domains, we search for those
        }
        else if ( c == '.' ) {
            // dots are acceptable in both, but consecutive dots
            // do not appear in domains.a
            if ( s[i+1] == '.' && domain )
                return false;
        }
        else if ( domain ) {
            // we summarily reject domains that contain ", :, \ and so on
            return false;
        }
        else if ( c == '<' || c == '>' || c == '@' ) {
            // those three characters are highly suspect in localparts
            // and illegal in domains. if we're asked to search for
            // them, that's probably an IMAP clent on crack (do you
            // hear that, rsa.com?)
            return false;
        }
        ++i;
    }
    return true;
}


static void addAddressTerm( EStringList * terms,
                            Selector * root,
                            const EString & jn,
                            const char * part,
                            const UString & s,
                            bool isPrefix,
                            bool isPostfix )
{
    bool ascii = true;
    uint i = 0;
    while ( i < s.length() && ascii ) {
        if ( s[i] > 127 || s[i] < 32 )
            ascii = false;
        ++i;
    }
    EString r;
    if ( ascii )
        r.append( "lower(" );
    r.append( "a" );
    r.append( jn );
    r.append( "." );
    r.append( part );
    if ( ascii )
        r.append( ")" );
    uint b;
    if ( ascii )
        b = root->placeHolder( s.ascii().lower() );
    else
        b = root->placeHolder( s );
    if ( isPrefix && isPostfix ) {
        if ( ascii )
            r.append( "=" );
        else
            r.append( " ilike " );
        r.append( "$" );
        r.appendNumber( b );
    }
    else {
        if ( ascii )
            r.append( " like " );
        else
            r.append( " ilike " );
        if ( !isPrefix )
            r.append( "'%'||" );
        r.append( "$" );
        r.appendNumber( b );
        if ( !isPostfix )
            r.append( "||'%'" );
    }
    terms->append( r );
}


/*! This implements searching for the given address \a fields, or
    on all address fields if \a fields is the empty list.

    XXX: This comment may be wrong.
*/

EString Selector::whereAddressFields( List<Selector> * fields )
{
    UStringList names;
    List<Selector>::Iterator si( fields );
    while ( si ) {
        names.append( si->d->s16 );
        ++si;
    }
    names.removeDuplicates( false );

    bool knownMatch = false;

    // put together the initial part of the join
    uint join = ++root()->d->join;
    EString jn = fn( join );

    EStringList addresses;

    UStringList::Iterator n( names );
    while ( n ) {
        UString name = *n;
        ++n;
        // analyse the search term to see whether we have to look at it
        // everywhere or whether we can perhaps do it cleverly.
        int at = name.find( '@' );
        int lt = name.find( '<' );
        if ( lt >= 0 && name.find( '@', lt ) )
            at = name.find( '@', lt );
        int gt = name.find( '>' );
        if ( at >= 0 && name.find( '>', at ) )
            gt = name.find( '>', at );

        // look for the domain candidate
        UString dom;
        bool domPrefix = false;
        bool domPostfix = false;
        if ( at >= 0 && gt > 0 ) {
            // an entire domain perhaps?
            dom = name.mid( at + 1, gt - at - 1 );
            domPrefix = true;
            domPostfix = true;
        }
        else if ( at >= 0 ) {
            // a domain prefix
            dom = name.mid( at + 1 );
            domPrefix = true;
        }
        else if ( gt >= 0 ) {
            // a domain postfix
            dom = name.mid( 0, gt );
            domPostfix = true;
        }
        else {
            // no idea really
            dom = name;
        }

        // look for the localpart candidate
        UString lp;
        bool lpPrefix = false;
        bool lpPostfix = false;
        if ( lt >= 0 && at > lt ) {
            // an entire localpart
            lp = name.mid( lt + 1, at - lt - 1 );
            lpPrefix = true;
            lpPostfix = true;
        }
        else if ( at >= 0 ) {
            // a postfix
            lp = name.mid( 0, at );
            lpPostfix = true;
        }
        else if ( lt >= 0 ) {
            lp = name.mid( lt + 1 );
            lpPrefix = true;
        }
        else {
            lp = name;
        }

        // the name is... hm...
        UString dn;
        bool dnPostfix = false;
        if ( lt >= 0 ) {
            dn = name.mid( 0, lt ).simplified();
            dnPostfix = true;
        }
        else if ( at >= 0 || gt >= 0 ) {
            // we're looking for e.g. asdf@asdf or asdf>, so we just don't
            // have a display-name
        }
        else {
            dn = name;
        }

        bool canMatch = true;

        bool dnUsed = false;
        if ( !dn.isEmpty() ) {
            dnUsed = true;
        }
        bool lpUsed = false;
        if ( lp.isEmpty() ) {
            if ( lpPrefix && lpPostfix )
                canMatch = false;
        }
        else if ( addressPartLegal( lp, false ) ) {
            lpUsed = true;
        }
        else {
            if ( lpPrefix || lpPostfix )
                canMatch = false;
            lpUsed = false;
        }
        bool domUsed = false;
        if ( dom.isEmpty() ) {
            if ( domPrefix && domPostfix )
                canMatch = false;
        }
        else if ( addressPartLegal( dom, true ) ) {
            domUsed = true;
        }
        else {
            if ( domPrefix || domPostfix )
                canMatch = false;
            domUsed = false;
        }

        EString fieldLimit;
        bool matchesFrom = false;
        if ( canMatch ) {
            IntegerSet fieldsUsed;
            List<Selector>::Iterator si( fields );
            while ( si ) {
                if ( si->d->s16 == name ) {
                    if ( si->d->s8.isEmpty() ) {
                        fieldsUsed.add( 1, HeaderField::LastAddressField );
                    }
                    else {
                        uint t = HeaderField::fieldType( si->d->s8 );
                        if ( t <= HeaderField::LastAddressField )
                            fieldsUsed.add( t );
                    }
                }
                ++si;
            }
            if ( fieldsUsed.contains( HeaderField::From ) )
                matchesFrom = true;
            if ( fieldsUsed.count() < HeaderField::LastAddressField ) {
                uint x = 1;
                EStringList l;
                while ( x <= fieldsUsed.count() ) {
                    l.append( "af" + jn + ".field=" +
                              fn( fieldsUsed.value( x ) ) );
                    x++;
                }
                if ( l.count() == 1 )
                    fieldLimit = *l.first();
                else
                    fieldLimit = "(" + l.join( " or " ) + ")";
            }
        }

        if ( matchesFrom && name.isEmpty() && !dnUsed && !lpUsed && !domUsed )
            knownMatch = true;

        if ( canMatch && !knownMatch ) {
            EStringList terms;
            if ( dnUsed )
                addAddressTerm( &terms, root(), jn,
                                "name", dn, false, dnPostfix );
            if ( lpUsed )
                addAddressTerm( &terms, root(),  jn,
                                "localpart", lp, lpPrefix, lpPostfix );
            if ( domUsed )
                addAddressTerm( &terms, root(), jn,
                                "domain", dom, domPrefix, domPostfix );

            EString s;
            if ( terms.isEmpty() ) {
                if ( !fieldLimit.isEmpty() )
                    s.append( fieldLimit );
            }
            else if ( terms.count() == 1 ||
                      ( lpUsed && ( lpPrefix || lpPostfix ) ) ||
                      ( domUsed && ( domPrefix || domPostfix ) ) ) {
                s = "(";
                if ( !fieldLimit.isEmpty() )
                    terms.prepend( new EString( fieldLimit ) );
                s.append( terms.join( " and " ) );
                s.append( ")" );
            }
            else {
                bool p = false;
                if ( !fieldLimit.isEmpty() ) {
                    s = "(";
                    p = true;
                    s.append( fieldLimit );
                    s.append( " and " );
                }
                s.append( "(" );
                s.append( terms.join( " or " ) );
                s.append( ")" );
                if ( p )
                    s.append( ")" );
            }

            addresses.append( s );
        }

    }

    // after all that, we finally have what we need to put together
    // the join condition
    EString r = " left join address_fields af" + jn +
                " on (af" + jn + ".message=" + mm() + ".message)"
                " left join addresses a" + jn +
                " on (a" + jn + ".id=af" + jn + ".address";

    if ( !addresses.isEmpty() ) {
        r.append( " and " );
        if ( addresses.count() > 1 )
            r.append( "(" );
        r.append( addresses.join( " or " ) );
        if ( addresses.count() > 1 )
            r.append( ")" );
    }
    r.append( ")" );

    // finally, bang in the join and return a "not"-wrappable test of
    // whether the join found something
    root()->d->leftJoins.append( r );
    return "a" + jn + ".id is not null";
}


/*! This implements searches on all header fields.
*/

EString Selector::whereHeader()
{
    if ( d->s16.isEmpty() )
        return "true"; // there _is_ at least one header field ;)

    uint like = placeHolder( q( d->s16 ) );
    EString jn = "hf" + fn( ++root()->d->join );
    EString j = " left join header_fields " + jn +
               " on (" + mm() + ".message=" + jn + ".message and " +
               jn + ".part='' and " +
               jn + ".value ilike " + matchAny( like ) + ")";
    root()->d->leftJoins.append( j );
    List<Selector> dummy;
    dummy.append( this );
    return "(" + jn + ".field is not null or " +
        whereAddressFields( &dummy ) + ")";
}


/*! This implements searches on (text) bodyparts. We cannot and will
    not do "full-text" search on the contents of e.g. jpeg
    pictures. (For some formats we search on the text part, because
    the injector sets bodyparts.text based on bodyparts.data.)

    This function uses full-text search if available, but filters the
    results with a plain 'ilike' in order to avoid overly liberal
    stemming. (Perhaps we actually want liberal stemming. I don't
    know. IMAP says not to do it, but do we listen?)
*/

EString Selector::whereBody()
{
    root()->d->needBodyparts = true;

    EString s;

    uint bt = placeHolder( q( d->s16 ) );

    if ( ::tsearchAvailable && sensibleWords( d->s16 ) )
        s.append( "(" + matchTsvector( "bp.text", bt ) + " "
                  "and bp.text ilike " + matchAny( bt ) + ")" );
    else
        s.append( "bp.text ilike " + matchAny( bt ) );

    return s;
}


/*! This implements searches on the rfc822size of messages.
*/

EString Selector::whereRfc822Size()
{
    root()->d->needMessages = true;
    uint s = placeHolder();
    root()->d->query->bind( s, d->n );
    if ( d->a == Smaller )
        return m() + ".rfc822size<$" + fn( s );
    else if ( d->a == Larger )
        return m() + ".rfc822size>$" + fn( s );
    setError( "Internal error: " + debugString() );
    return "";
}


/*! This implements searches on whether a message has/does not have
    flags.
*/

EString Selector::whereFlags()
{
    if ( d->s8 == "\\recent" ) {
        if ( !root()->d->session )
            return "false";
        // the database cannot look at the recent flag, so we turn
        // this query into a test for the relevant UIDs.
        return whereSet( root()->d->session->recent() );
    }

    uint fid = Flag::id( d->s8 );
    if ( Flag::isSeen( fid ) )
        return mm() + ".seen";
    else if ( Flag::isDeleted( fid ) )
        return mm() + ".deleted";

    uint join = ++root()->d->join;
    EString n = fn( join );

    EString j;
    if ( fid ) {
        // we know this flag, so look for it reasonably efficiently
        j = " left join flags f" + n +
            " on (" + mm() + ".mailbox=f" + n + ".mailbox and " +
            mm() + ".uid=f" + n + ".uid and "
            "f" + n + ".flag=" + fn( fid ) + ")";
    }
    else {
        // just in case the cache is out of date we look in the db
        uint b = placeHolder( d->s8.lower() );
        j = " left join flags f" + n +
            " on (" + mm() + ".mailbox=f" + n + ".mailbox and " +
            mm() + ".uid=f" + n + ".uid and f" + n + ".flag="
            "(select id from flag_names where lower(name)=$" + fn(b) + "))";
    }
    root()->d->leftJoins.append( j );

    // finally use the join in a manner which doesn't accidentally
    // confuse different flags.
    return "f" + n + ".flag is not null";
}


/*! Returns a condition to match the numbers in \a s. Binds 0-2
    variables.
*/

EString Selector::whereSet( const IntegerSet & s )
{
    if ( s.isEmpty() )
        return "false";

    uint u = placeHolder();
    uint c = s.count();

    if ( c > 2 ) {
        root()->d->query->bind( u, s );
        return mm() + ".uid=any($" + fn( u ) + ")";
    }

    if ( c == 2 ) {
        uint u2 = placeHolder();
        root()->d->query->bind( u, s.smallest() );
        root()->d->query->bind( u2, s.largest() );
        return "(" + mm() + ".uid=$" + fn( u ) +
            " or " + mm() + ".uid=$" + fn( u2 ) + ")";
    }

    root()->d->query->bind( u, s.smallest() );
    return mm() + ".uid=$" + fn( u );
}


/*! This implements searches on whether a message has the right UID.
*/

EString Selector::whereUid()
{
    return whereSet( d->s );
}


/*! This implements searches on whether a message has/does not have
    the right annotation.
*/

EString Selector::whereAnnotation()
{
    root()->d->needAnnotations = true;

    uint pattern = placeHolder();
    EString join = fn( ++root()->d->join );
    root()->d->leftJoins.append(
        " left join annotation_names an" + join +
        " on (a.name=an" + join + ".id"
        " and an" + join + ".name like $" + fn( pattern ) + ")"
        );
    EString sql = 0;
    uint i = 0;
    while ( i < d->s8.length() ) {
        if ( d->s8[i] == '*' )
            sql.append( '%' );
        else
            sql.append( d->s8[i] );
        i++;
    }
    root()->d->query->bind( pattern, sql );

    EString user;
    EString attribute;
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

    EString like = "is not null";
    if ( !d->s16.isEmpty() ) {
        uint i = placeHolder( q( d->s16 ) );
        like = "ilike " + matchAny( i );
    }

    return "(" + user + " and an" + join +
        " is not null and value " + like + ")";
}


/*! This implements the modseq search-key. */

EString Selector::whereModseq()
{
    uint i = placeHolder();
    root()->d->query->bind( i, d->n );

    if (action() == Larger )
        return mm() + ".modseq>=$" + fn( i );
    else if ( action() == Smaller )
        return mm() + ".modseq<$" + fn( i );

    log( "Bad selector", Log::Error );
    return "false";
}


/*! This implements the older/younger search-keys. */

EString Selector::whereAge()
{
    uint i = placeHolder();
    EString r;
    if ( mm().startsWith( "d" ) ) {
        root()->d->query->bind( i, d->n );
        r = mm() + ".deleted_at";
        if ( d->a == Larger )
            r += "<=";
        else
            r += ">=";
        r += "(current_timestamp - interval '1 second' * $" + fn( i ) + ")";
    }
    else {
        root()->d->needMessages = true;
        root()->d->query->bind( i, (uint)::time( 0 ) - d->n );
        if ( d->a == Larger )
            r = m() + ".idate<=$" + fn( i );
        else
            r = m() + ".idate>=$" + fn( i );
    }
    return r;
}


/*! This implements the emailid search-key. */

EString Selector::whereDatabaseId()
{
    uint i = placeHolder();
    root()->d->query->bind( i, d->n );

    if ( action() == Equals )
        return mm() + ".message=$" + fn( i );

    log( "Bad selector", Log::Error );
    return "false";
}


/*! This implements the threadid search-key. */

EString Selector::whereThreadId()
{
    uint i = placeHolder();
    root()->d->query->bind( i, d->n );

    if ( action() == Equals ) {
        root()->d->needMessages = true;
        return m() + ".thread_root=$" + fn( i );
    }

    log( "Bad selector", Log::Error );
    return "false";

}


static bool isAddressField( const EString & s )
{
    uint t = HeaderField::fieldType( s );
    if ( t > 0 && t <= HeaderField::LastAddressField )
        return true;
    return false;
}


/*! This implements any search that's not bound to a specific field,
    generally booleans and "all".

    As a hack, oops, as an optimization, this function also looks for
    an OR list of address-field searches, and if any, lifts the shared
    parts of those searches out so the DBMS processes the search
    faster.
*/

EString Selector::whereNoField()
{
    if ( d->a == And ) {
        bool f = false;
        int oldPlaceholder = root()->d->placeholder;
        EStringList conditions;
        List<Selector>::Iterator i( d->children );
        while ( i ) {
            EString w = i->where();
            if ( w == "false" )
                f = true;
            else if ( w != "true" )
                conditions.append( w );
            ++i;
        }
        if ( conditions.isEmpty() )
            return "true";
        if ( f && oldPlaceholder == root()->d->placeholder )
            return "false";
        if ( conditions.count() == 1 )
            return conditions.join( "" );
        EString r;
        r.append( "(" );
        r.append( conditions.join( " and " ) );
        r.append( ")" );
        return r;
    }
    else if ( d->a == Or ) {
        List<Selector> addressTests;
        List<Selector> otherHeaderTests;
        List<Selector> rest;

        List<Selector>::Iterator i( d->children );
        while ( i ) {
            if ( i->d->f == Header ) {
                if ( i->d->s8.isEmpty() ) {
                    addressTests.append( i );
                    otherHeaderTests.append( i );
                }
                else if ( isAddressField( i->d->s8 ) ) {
                    addressTests.append( i );
                }
                else {
                    otherHeaderTests.append( i );
                }
            }
            else {
                rest.append( i );
            }
            ++i;
        }

        EStringList conditions;
        List<Selector>::Iterator si( rest );
        while ( si ) {
            EString w = si->where();
            if ( w == "true" )
                return "true";
            conditions.append( w );
            ++si;
        }
        if ( !addressTests.isEmpty() )
            conditions.append( whereAddressFields( &addressTests ) );
        if ( !otherHeaderTests.isEmpty() )
            conditions.append( whereHeaders( &otherHeaderTests ) );

        if ( conditions.count() == 1 )
            return *conditions.first();
        return "(" + conditions.join( " or " ) + ")";
    }
    else if ( d->a == Not ) {
        EString c = d->children->first()->where();
        if ( c == "true" )
            return "false";
        else if ( c == "false" )
            return "true";
        else if ( c.endsWith( " is not null" ) )
            return c.mid( 0, c.length() - 8 ) + "null";
        return "not " + c;
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


/*! This implements a search that's bound to a specific mailbox or a
    subtree.

    This does no permission checking. query() includes a gargantuan
    clause to limit the search to mailboxes the user can read; this
    function relies on that clause.
*/

EString Selector::whereMailbox()
{
    IntegerSet ids;
    List<Mailbox> fifo;
    fifo.append( d->m );
    while ( !fifo.isEmpty() ) {
        Mailbox * m = fifo.shift();
        if ( m && m->id() && !m->deleted() )
            ids.add( m->id() );
        if ( d->mc && m )
            fifo.append( m->children() );
    }

    uint i = placeHolder();
    if ( ids.count() == 1 ) {
        root()->d->query->bind( i, ids.smallest() );
        return mm() + ".mailbox=$" + fn( i );
    }

    root()->d->query->bind( i, ids );
    return mm() + ".mailbox=any($" + fn( i ) + ")";
}


/*! This implements inthread, that is, a thread-specific search.

    Conceptually simple but perhaps a little hard on the RDBMS.
*/

EString Selector::whereInThread()
{
    root()->d->needMessages = true;
    EString join = fn( ++root()->d->join );
    EString * sm = new EString( "m" + join );
    EString * smm = new EString( "mm" + join );
    root()->d->extraJoins.append(
        " join messages " + *sm +
        " on (" + m() + ".thread_root=" + *sm + ".thread_root)"
        " join mailbox_messages " + *smm +
        " on (" + *smm + ".message=" + *sm + ".id"
        " and " + mm() + ".mailbox=mm" + join + ".mailbox)"
        );
    d->children->first()->d->msg = sm;
    d->children->first()->d->mm = smm;
    return d->children->first()->where();
}


/*! Give an ASCII representatation of this object, suitable for debug
    output or for equality testing.
*/

EString Selector::debugString() const
{
    EString r;

    EString o, w;

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
    case Equals:
        return "equals";
        break;
    case Special:
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
        return d->s.set();
        break;
    case Annotation:
        w = "annotation " + d->s8b + " of ";
        break;
    case MailboxTree:
        if ( d->mc )
            w = "subtree ";
        else
            w = "mailbox ";
        break;
    case InThread:
        w = "inthread";
        break;
    case Modseq:
        w = "modseq";
        break;
    case Age:
        w = "age";
        break;
    case DatabaseId:
        w = "database-id";
        break;
    case ThreadId:
        w = "thread-id";
        break;
    };

    r = w + " " + o + " ";
    if ( d->n )
        r.appendNumber( d->n );
    else if ( d->s16.isEmpty() )
        r.append( d->s8 );
    else if ( d->m )
        r.append( d->m->name().ascii() );
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


static uint lmatch( const EString & pattern, uint p,
                    const EString & name, uint n )
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


/*! Returns the string representation of this Selector. This is what's
    stored in the views.selector column in the database. */

EString Selector::string()
{
    Utf8Codec u;
    EString r( "(" );

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
        if ( d->f == Modseq )
            r.append( "modseqlarger" );
        else
            r.append( "messagelarger" );
        r.append( " " );
        r.appendNumber( d->n );
        break;
    case Smaller:
        r.append( "messagesmaller" );
        r.append( " " );
        r.appendNumber( d->n );
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
    case Equals:
        // ### not used, to be deleted in a following commit
        break;
    case Special:
        if ( d->f == InThread ) {
            r.append( "inthread" );
        }
        else if ( d->f == MailboxTree ) {
            r.append( "mailbox" ); // XXX needs more
        }
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

EString Selector::error()
{
    return root()->d->error;
}


/*! This static function takes a canonical string representation \a s,
    and returns the Selector corresponding to it, or 0 if there was a
    parsing error.
*/

Selector * Selector::fromString( const EString &s )
{
    Selector * r = new Selector;

    uint i = 0;

    if ( s[i++] != '(' )
        return 0;

    EString op;
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

            EString t = s.mid( j, i-j ).unquoted();

            if ( r->d->f == Uid ) {
                EStringList * l = EStringList::split( ',', t );
                EStringList::Iterator it( l );
                while ( it ) {
                    EStringList * range = EStringList::split( ':', *it );
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
        r->d->f = Rfc822Size;
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
    else if ( op == "modseqlarger" ) {
        r->d->f = Modseq;
        r->d->a = Larger;

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


/*! Returns the field specific using the constructor.

*/

Selector::Field Selector::field() const
{
    return d->f;
}


/*! Returns the action specified using the constructor.

*/

Selector::Action Selector::action() const
{
    return d->a;
}


/*! Returns a reference to the set passed to the constructor. If the
    constructor didn't accept a set, messageSet() returns a reference
    to an empty set.
*/

const IntegerSet & Selector::messageSet() const
{
    return d->s;
}


/*! Returns true if this Selector includes at least one dynamic
    message attribute (something which can change after message
    arrival). If dynamic(), then repeating the Selector's query() can
    yield different results. (That is of course the very subject of
    RFC 4551.)
*/

bool Selector::dynamic() const
{
    if ( d->f == Flags || d->f == Annotation || d->f == Modseq ||
         d->f == Age )
        return true;
    List< Selector >::Iterator i( d->children );
    while ( i ) {
        Selector * c = i;
        ++i;
        if ( c->dynamic() )
            return true;
    }
    return false;
}


/*! Returns true if this Selector includes at least one time-sensitive
    message attribute (something which can change as time passes). If
    the Selector is timeSensitive(), it is also dynamic().
*/

bool Selector::timeSensitive() const
{
    if ( d->f == Age )
        return true;
    List< Selector >::Iterator i( d->children );
    while ( i ) {
        Selector * c = i;
        ++i;
        if ( c->timeSensitive() )
            return true;
    }
    return false;
}


/*! Returns true if this Selector includes modseq logic, and false if
    not.
*/

bool Selector::usesModseq() const
{
    if ( d->f == Modseq )
        return true;
    List< Selector >::Iterator i( d->children );
    while ( i ) {
        Selector * c = i;
        ++i;
        if ( c->usesModseq() )
            return true;
    }
    return false;
}


/*! Returns the 8-bit string supplied to some constructors, or an
    empty string if none has been specified.
*/

EString Selector::stringArgument() const
{
    return d->s8;
}


/*! Returns the unicode string supplied to some constructors, or an
    empty string if none has been specified.
*/

UString Selector::ustringArgument() const
{
    return d->s16; // it's actually 32-bit, isn't it? who cares.
}


/*! Returns the numeric argument supplied to some constructors, or 0
    if none has been specified.
*/

int Selector::integerArgument() const
{
    return d->n;
}


/*! Returns the message set supplied to some constructors, or an empty
    set if none has been specified.
*/

IntegerSet Selector::messageSetArgument() const
{
    return d->s;
}


/*! Returns a pointer to this selector's children (only applicable for
    and/or/not selectors). May return a pointer to an empty list, but
    will never return a null pointer.
*/

List<Selector> * Selector::children()
{
    return d->children;
}


/*! Returns a string such as "mm", referring to the mailbox_messages
    table. This may also be "dm", "dm2", "mm42" or worse, if the
    search is really complex.
*/

EString Selector::mm()
{
    Selector * t = this;
    while ( t && !t->d->mm && t->d->parent )
        t = t->d->parent;
    if ( t->d->mm )
        return *t->d->mm;
    return "mm";
}


/*! Returns a string such as "m", referring to the messages
    table. This may also be "m2", "m2", "m42" or worse, if the
    search is really complex.
*/

EString Selector::m()
{
    Selector * t = this;
    while ( t && !t->d->msg && t->d->parent )
        t = t->d->parent;
    if ( t->d->msg )
        return *t->d->msg;
    return "m";
}


/*! Performs whatever duties the Selector needs to have performed at
    startup. Selector can be used even without calling setup().
*/

void Selector::setup()
{
    if ( !::retunerCreated )
        (void)new RetuningDetector;
}


/*! Returns a pointer to the mailbox on which this selector operates. */

Mailbox * Selector::mailbox() const
{
    return d->m;
}


/*! Returns true if this selector should match messages in children of
    mailbox(), and false if not.
*/

bool Selector::alsoChildren() const
{
    return d->mc;
}


class RetentionPoliciesCache
    : public Cache
{
public:
    class X: public EventHandler {
    public:
        X( RetentionPoliciesCache * rpc ): me( rpc ) {
            (void)new DatabaseSignal( "retention_policies_updated", this );
        }
        void execute() {
            me->retains.clear();
        }
        RetentionPoliciesCache * me;
    };
    RetentionPoliciesCache(): Cache( 5 ) {}
    void clear() { retains.clear(); }
    Map<Selector> retains;
};

static RetentionPoliciesCache * cache = 0;



class RetentionSelectorData
    : public Garbage
{
public:
    RetentionSelectorData()
        : m( 0 ), done( false ), q( 0 ),
          retains( 0 ), deletes( 0 ), owner( 0 ),
          transaction( 0 ) {}
    Mailbox * m;
    bool done;
    Query * q;
    Selector * retains;
    Selector * deletes;
    EventHandler * owner;
    Transaction * transaction;
};






/*! \class RetentionSelector selector.h

    The RetentionSelector class makes a Selector based on the
    retention_policies table, and produces queries to do what
    retention demands.

    Somewhat slow, perhaps. We'll have to add some caching so we don't
    select on retention_policies all the time.
*/


/*! Constructs a retention selector to find the messages in \a m that
    should be retained, and notifies \a h once done().

    Once execute() has been called and done() returns true, retains()
    and deletes() return a selector expressing those policies.

    The selector may be ready after the first execute(). In that case \a
    h is not notified separately.
*/

RetentionSelector::RetentionSelector( Mailbox * m, EventHandler * h )
    : d( new RetentionSelectorData )
{
    d->m = m;
    d->owner = h;
    if ( !m )
        return;

    if ( !::cache )
        ::cache = new RetentionPoliciesCache;
    Selector * s = ::cache->retains.find( m->id() );
    if ( !s )
        return;

    d->done = true;
    if ( !s->children()->isEmpty() )
        d->retains = s;
}


/*! Constructs a RetentionSelector to cook up the giant 'insert into
    deleted_messages' query aox vacuum needs, using \a t. Will
    notify() \a h when done(). You have to call execute() once.
*/

RetentionSelector::RetentionSelector( Transaction * t, EventHandler * h )
    : d( new RetentionSelectorData )
{
    d->owner = h;
    d->transaction = t;
}


void RetentionSelector::execute()
{
    if ( d->done )
        return;

    if ( !d->q ) {
        if ( d->m ) {
            // we're looking for 'retain' policies that apply to d->m
            IntegerSet ids;
            Mailbox * m = d->m;
            while ( m ) {
                if ( m->id() && !m->deleted() )
                    ids.add( m->id() );
                m = m->parent();
            }
            if ( ids.isEmpty() ) {
                // no mailboxes, so no policies. note no owner->notify().
                d->done = true;
                return;
            }
            if ( ids.count() == 1 ) {
                d->q = new Query( "select duration, selector, action, id "
                                  "from retention_policies "
                                  "where mailbox=$1 and action='retain'",
                                  this );
                d->q->bind( 1, ids.smallest() );
            }
            else {
                d->q = new Query( "select duration, selector, action, id "
                                  "from retention_policies "
                                  "where mailbox=any($1) and action='retain'",
                                  this );
                d->q->bind( 1, ids );
            }
        }
        else {
            // we need ALL policies
            d->q = new Query( "select duration, selector, action, mailbox, id "
                              "from retention_policies",
                              this );
        }
        if ( d->transaction )
            d->transaction->enqueue( d->q );
        else
            d->q->execute();
    }

    if ( !d->q->done() )
        return;

    d->done = true;

    d->retains = new Selector( Selector::Or );
    d->deletes = new Selector( Selector::Or );

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        Selector * s = new Selector( Selector::And );
        Selector::Action action = Selector::Smaller;
        if ( !d->m && !r->isNull( "mailbox" ) ) {
            Mailbox * subtree = Mailbox::find( r->getInt( "mailbox" ) );
            s->add( new Selector( subtree, true ) );
        }
        if ( r->getEString( "action" ) == "delete" )
            action = Selector::Larger;
        if ( !r->isNull( "selector" ) )
            s->add( Selector::fromString( r->getEString( "selector" ) ) );
        uint duration = r->getInt( "duration" );
        if ( duration )
            s->add( new Selector( Selector::Age, action, duration * 86400 ) );
        if ( action == Selector::Smaller )
            d->retains->add( s );
        else
            d->deletes->add( s );
    }

    if ( d->m && ::cache )
        ::cache->retains.insert( d->m->id(), d->retains );

    if ( d->retains->children()->isEmpty() )
        d->retains = 0;
    if ( d->deletes->children()->isEmpty() )
        d->deletes = 0;

    if ( d->owner )
        d->owner->notify();
}


/*! Returns true if the object is done, false if it's still working. */

bool RetentionSelector::done()
{
    return d->done;
}


/*! Returns a pointer to the Selector that will match all messages
    that need to be retained, or 0 if there is no applicable retention
    policy.

    Selector::simplify() has not been called.

*/

Selector * RetentionSelector::retains()
{
    return d->retains;
}


/*! Returns a pointer to the Selector that will match all messages
    that need to be deleted, or 0 if there is no applicable retention
    policy.

    Selector::simplify() has not been called.

*/

Selector * RetentionSelector::deletes()
{
    return d->deletes;
}
