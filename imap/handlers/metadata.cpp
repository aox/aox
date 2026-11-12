// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "metadata.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "estring.h"
#include "estringlist.h"
#include "imapparser.h"
#include "permissions.h"
#include "transaction.h"


class MetadataEntry
    : public Garbage
{
public:
    MetadataEntry(): nil( false ) {}

    EString name;
    EString value;
    bool nil;
};


class MetadataData
    : public Garbage
{
public:
    MetadataData()
        : type( Metadata::Get ), state( 0 ), mailbox( 0 ),
          permissions( 0 ), q( 0 ), count( 0 ),
          values( new List<MetadataEntry> ),
          depth( 0 ), maxSize( 0 ), shared( false )
    {}

    Metadata::Type type;
    uint state;
    Mailbox * mailbox;
    Permissions * permissions;
    Query * q;
    Query * count;
    EStringList entries;
    List<MetadataEntry> * values;
    uint depth;
    uint maxSize;
    bool shared;
};


/*! \class Metadata metadata.h

    The Metadata class implements the GETMETADATA and SETMETADATA
    commands from RFC5464, for both server entries (the mailbox name
    is the empty string) and mailbox entries.

    Private entries belong to one user and shared entries to
    everyone, as the first component of the entry name says. We do not
    send unsolicited METADATA responses, which RFC5464 4.4 permits.

    Shared server entries are readable but not writable: /shared/admin
    is read-only by definition, and letting any user change a value
    every user sees is not something I want to offer over IMAP. Shared
    *mailbox* entries can be written by anyone with the RFC4314 "n"
    right, which is what that right is for, and which is how Kolab
    stores its folder types.
*/


/*! The biggest value we store. RFC5464 4.1 requires at least 1024. */

static const uint maxValueSize = 65536;


/*! The most entries one user can have in one scope. RFC5464 4.1
    requires at least 10.
*/

static const uint maxEntries = 100;


/*! Returns true if \a name is a valid entry name per RFC5464 3.2, and
    false if using it should result in a BAD response. If \a prefix is
    true, \a name is used with DEPTH to name a subtree rather than an
    entry, and a bare /private or /shared is good enough.

    RFC5464 3.2 says entry names have at least two components, so a
    strict reading makes "GETMETADATA (DEPTH infinity) INBOX /private"
    a syntax error. Enumerating everything a mailbox has is a fair
    thing to ask for, and /private is not being used as an entry name
    there, so we answer it.
*/

static bool validName( const EString & name, bool prefix = false )
{
    if ( !name.startsWith( "/" ) || name.endsWith( "/" ) ||
         name.contains( "//" ) )
        return false;

    uint i = 0;
    while ( i < name.length() ) {
        char c = name[i];
        if ( c < 0x20 || (unsigned char)c >= 0x7f ||
             c == '*' || c == '%' )
            return false;
        i++;
    }

    EStringList * l = EStringList::split( '/', name.mid( 1 ) );
    if ( l->count() < 2 && !prefix )
        return false;
    EStringList::Iterator c( l );
    if ( *c != "private" && *c != "shared" )
        return false;
    ++c;
    if ( c && *c == "vendor" && l->count() < 4 )
        return false;
    return true;
}


/*! Returns the number of components \a name has below \a prefix, or 0
    if it is not below \a prefix at all. Both are lower-cased entry
    names.
*/

static uint depthBelow( const EString & name, const EString & prefix )
{
    if ( !name.startsWith( prefix + "/" ) )
        return 0;
    uint d = 1;
    uint i = prefix.length() + 1;
    while ( i < name.length() ) {
        if ( name[i] == '/' )
            d++;
        i++;
    }
    return d;
}


/*! Creates a new handler for GETMETADATA or SETMETADATA, as \a t says. */

Metadata::Metadata( Type t )
    : d( new MetadataData )
{
    d->type = t;
}


void Metadata::parse()
{
    space();

    // getmetadata = "GETMETADATA" [SP getmetadata-options]
    //               SP mailbox SP entries
    if ( d->type == Get && nextChar() == '(' ) {
        step();
        while ( ok() ) {
            EString option = atom().lower();
            if ( option == "maxsize" ) {
                space();
                d->maxSize = number();
            }
            else if ( option == "depth" ) {
                space();
                EString v = atom().lower();
                if ( v == "0" )
                    d->depth = 0;
                else if ( v == "1" )
                    d->depth = 1;
                else if ( v == "infinity" )
                    d->depth = (uint)-1;
                else
                    error( Bad, "DEPTH must be 0, 1 or infinity" );
            }
            else {
                error( Bad, "Unknown GETMETADATA option: " + option );
            }
            if ( nextChar() != ' ' )
                break;
            space();
        }
        require( ")" );
        space();
    }

    // an empty mailbox name means the server. mailbox() cannot parse
    // that - it resolves a relative name against the user's home, and
    // the home with a trailing slash is not a valid name - so look
    // first and parse the name properly only if there is one.
    uint m = parser()->mark();
    if ( !astring().isEmpty() ) {
        parser()->restore( m );
        d->mailbox = mailbox();
    }
    space();

    if ( d->type == Get ) {
        bool list = false;
        if ( nextChar() == '(' ) {
            step();
            list = true;
        }
        while ( ok() ) {
            d->entries.append( new EString( astring() ) );
            if ( nextChar() != ' ' )
                break;
            space();
        }
        if ( list )
            require( ")" );
    }
    else {
        require( "(" );
        while ( ok() ) {
            MetadataEntry * e = new MetadataEntry;
            e->name = astring();
            space();
            char c = nextChar();
            if ( c == '"' || c == '{' || c == '~' ) {
                e->value = string();
            }
            else {
                nil();
                e->nil = true;
            }
            d->values->append( e );
            if ( nextChar() != ' ' )
                break;
            space();
        }
        require( ")" );
    }

    end();
}


/*! Returns true if the user may see annotations on the mailbox this
    works on, and false if not. RFC5464 3.3 wants the "l" right and
    any one of "r", "s", "w", "i" and "p".
*/

bool Metadata::accessible() const
{
    Permissions * p = d->permissions;
    if ( !p->allowed( Permissions::Lookup ) )
        return false;
    return p->allowed( Permissions::Read ) ||
        p->allowed( Permissions::KeepSeen ) ||
        p->allowed( Permissions::Write ) ||
        p->allowed( Permissions::Insert ) ||
        p->allowed( Permissions::Post );
}


void Metadata::execute()
{
    if ( d->state == 0 ) {
        EStringList::Iterator e( d->entries );
        while ( e ) {
            if ( !validName( e->lower(), d->depth > 0 ) ) {
                error( Bad, "Invalid entry name: " + *e );
                return;
            }
            ++e;
        }
        List<MetadataEntry>::Iterator v( d->values );
        while ( v ) {
            if ( !validName( v->name.lower() ) ) {
                error( Bad, "Invalid entry name: " + v->name );
                return;
            }
            if ( v->value.length() > maxValueSize ) {
                setRespTextCode( "METADATA MAXSIZE " + fn( maxValueSize ) );
                error( No, "Value for " + v->name + " is too big" );
                return;
            }
            if ( v->name.lower().startsWith( "/shared/" ) )
                d->shared = true;
            ++v;
        }

        if ( d->type == Set && !d->mailbox && d->shared ) {
            error( No, "Shared server annotations are read-only" );
            return;
        }

        if ( d->mailbox )
            d->permissions = new Permissions( d->mailbox, imap()->user(),
                                              this );
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( d->permissions ) {
            if ( !d->permissions->ready() )
                return;
            if ( !accessible() ) {
                error( No, d->mailbox->name().ascii() +
                       " is not accessible" );
                return;
            }
            if ( d->type == Set && d->shared &&
                 !d->permissions->allowed(
                     Permissions::WriteSharedAnnotation ) ) {
                error( No, "Cannot write shared annotations on " +
                       d->mailbox->name().ascii() );
                return;
            }
        }

        if ( d->type == Get ) {
            if ( d->mailbox ) {
                d->q = new Query( "select name, value from metadata "
                                  "where mailbox=$1 "
                                  "and coalesce(owner,0) in (0,$2) "
                                  "order by name", this );
                d->q->bind( 1, d->mailbox->id() );
                d->q->bind( 2, imap()->user()->id() );
            }
            else {
                d->q = new Query( "select name, value from metadata "
                                  "where mailbox is null "
                                  "and coalesce(owner,0) in (0,$1) "
                                  "order by name", this );
                d->q->bind( 1, imap()->user()->id() );
            }
            d->q->execute();
        }
        else {
            // the delete and insert below are two statements, so they
            // need the table to themselves: nothing else serialises
            // two clients setting the same entry at the same time
            setTransaction( new Transaction( this ) );
            transaction()->enqueue( "lock metadata in exclusive mode" );
            List<MetadataEntry>::Iterator v( d->values );
            while ( v ) {
                EString name = v->name.lower();
                bool shared = name.startsWith( "/shared/" );
                Query * q
                    = new Query( "delete from metadata "
                                 "where coalesce(mailbox,0)=$1 "
                                 "and coalesce(owner,0)=$2 and name=$3", 0 );
                q->bind( 1, d->mailbox ? d->mailbox->id() : 0 );
                q->bind( 2, shared ? 0 : imap()->user()->id() );
                q->bind( 3, name );
                transaction()->enqueue( q );
                if ( !v->nil ) {
                    q = new Query( "insert into metadata "
                                   "(mailbox, owner, name, value) "
                                   "values ($1,$2,$3,$4)", 0 );
                    if ( d->mailbox )
                        q->bind( 1, d->mailbox->id() );
                    else
                        q->bindNull( 1 );
                    if ( shared )
                        q->bindNull( 2 );
                    else
                        q->bind( 2, imap()->user()->id() );
                    q->bind( 3, name );
                    q->bind( 4, v->value, Query::Binary );
                    transaction()->enqueue( q );
                }
                ++v;
            }
            d->count = new Query( "select count(*)::int as entries "
                                  "from metadata "
                                  "where coalesce(mailbox,0)=$1 "
                                  "and coalesce(owner,0) in (0,$2)", this );
            d->count->bind( 1, d->mailbox ? d->mailbox->id() : 0 );
            d->count->bind( 2, imap()->user()->id() );
            transaction()->enqueue( d->count );
            transaction()->execute();
        }
        d->state = 2;
    }

    if ( d->state == 2 && d->type == Get ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            error( No, "Database error: " + d->q->error() );
            return;
        }

        uint longest = 0;
        EStringList values;
        Row * r;
        while ( (r=d->q->nextRow()) != 0 ) {
            EString name = r->getEString( "name" );
            EString value;
            if ( !r->isNull( "value" ) )
                value = r->getEString( "value" );

            // which of the entries the client asked for does this
            // answer, and under which name do we report it?
            EString reported;
            EStringList::Iterator e( d->entries );
            while ( e && reported.isEmpty() ) {
                EString wanted = e->lower();
                if ( wanted == name )
                    reported = *e;
                else if ( d->depth &&
                          depthBelow( name, wanted ) &&
                          depthBelow( name, wanted ) <= d->depth )
                    reported = name;
                ++e;
            }
            if ( reported.isEmpty() )
                continue;

            if ( d->maxSize && value.length() > d->maxSize ) {
                if ( value.length() > longest )
                    longest = value.length();
                continue;
            }

            values.append( new EString( reported + " " +
                                        imapQuoted( value,
                                                    PlainString ) ) );
        }

        // an entry-values list cannot be empty, so a GETMETADATA that
        // matched nothing sends no METADATA response at all
        if ( !values.isEmpty() )
            respond( "METADATA " +
                     ( d->mailbox ? imapQuoted( d->mailbox )
                                  : EString( "\"\"" ) ) +
                     " (" + values.join( " " ) + ")" );
        if ( longest )
            setRespTextCode( "METADATA LONGENTRIES " + fn( longest ) );

        finish();
        return;
    }

    if ( d->state == 2 ) {
        if ( !d->count->done() )
            return;

        uint entries = 0;
        Row * r = d->count->nextRow();
        if ( r )
            entries = r->getInt( "entries" );
        if ( entries > maxEntries ) {
            d->state = 4;
            transaction()->rollback();
            setRespTextCode( "METADATA TOOMANY" );
            error( No, "Too many annotations" );
            return;
        }
        transaction()->commit();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !transaction()->done() )
            return;
        if ( transaction()->failed() ) {
            error( No, "Database error: " + transaction()->error() );
            return;
        }
        finish();
    }
}
