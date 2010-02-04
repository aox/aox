// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "imapurlfetcher.h"

#include "user.h"
#include "date.h"
#include "event.h"
#include "message.h"
#include "fetcher.h"
#include "imapparser.h"
#include "messagecache.h"
#include "handlers/fetch.h"
#include "handlers/section.h"
#include "permissions.h"
#include "estringlist.h"
#include "mailbox.h"
#include "query.h"
#include "md5.h"


struct UrlLink
    : public Garbage
{
    UrlLink( ImapUrl * u )
        : url( u ), mailbox( 0 ), message( 0 ),
          section( 0 ), permissions( 0 ), q( 0 )
    {}

    ImapUrl * url;
    Mailbox * mailbox;
    Message * message;
    Section * section;
    Permissions * permissions;
    Query * q;
};


struct MailboxSet
    : public Garbage
{
    MailboxSet( Mailbox * m )
        : mailbox( m )
    {}

    Mailbox * mailbox;
    IntegerSet a;
    IntegerSet h;
    IntegerSet b;
    IntegerSet i;
};


class IufData
    : public Garbage
{
public:
    IufData()
        : state( 0 ), done( false ), urls( 0 ), owner( 0 ),
          checker( 0 ), fetchers( 0 ), findIds( 0 )
    {}

    int state;
    bool done;
    EString error;
    EString badUrl;
    List<UrlLink> * urls;
    EventHandler * owner;
    PermissionsChecker * checker;
    List<Fetcher> * fetchers;
    Query * findIds;
};


/*! \class ImapUrlFetcher imapurlfetcher.h
    Returns the texts referenced by a List of IMAP URLs.

    This class takes a list of ImapUrls and retrieves the corresponding
    text from the database, subject to validation and access control. It
    is the basis for our CATENATE/URLFETCH/BURL support.

    For each submitted URL, this class does the following:

    1. Verify that the ImapUrl::user() is valid.
    2. Verify that the ImapUrl::mailboxName() refers to an existing
       mailbox in the relevant user's namespace; and, if the URL has
       a UIDVALIDITY, check that it's the same as that of the mailbox.
    3. Verify that the user has read access to that mailbox.
    4. Fetch the access key for that (user,mailbox).
    5. Verify that the URLAUTH token matches the URL. (We assume that
       the caller has checked ImapUrl::access() already.)
    6. Verify that the URL has not EXPIREd.
    7. Fetch and set the text corresponding to the URL.
    8. Notify the caller of completion.
*/

/*! Creates an ImapUrlFetcher object to retrieve the ImapUrls in the
    list \a l for the EventHandler \a ev, which will be notified upon
    completion. The URL objects in \a l are assumed to be valid.
*/

ImapUrlFetcher::ImapUrlFetcher( List<ImapUrl> * l, EventHandler * ev )
    : d( new IufData )
{
    d->owner = ev;
    d->urls = new List<UrlLink>;
    List<ImapUrl>::Iterator it( l );
    while ( it ) {
        d->urls->append( new UrlLink( it ) );
        ++it;
    }
}


void ImapUrlFetcher::execute()
{
    if ( d->state == 0 ) {
        if ( d->urls->isEmpty() ) {
            d->done = true;
            return;
        }

        List<UrlLink>::Iterator it( d->urls );
        while ( it ) {
            ImapUrl * url = it->url;
            if ( url->user() == 0 ) {
                setError( "invalid URL", url->orig() );
                return;
            }
            else if ( url->user()->state() == User::Unverified ) {
                url->user()->refresh( this );
            }
            ++it;
        }

        d->state = 1;
    }

    if ( d->state == 1 ) {
        d->checker = new PermissionsChecker;

        List<UrlLink>::Iterator it( d->urls );
        while ( it ) {
            ImapUrl * url = it->url;
            User * user = url->user();
            if ( user->state() == User::Unverified ) {
                return;
            }
            else if ( user->state() == User::Nonexistent ) {
                setError( "invalid URL", url->orig() );
                d->owner->execute();
                return;
            }
            else {
                Mailbox * m = user->mailbox( url->mailboxName() );
                if ( !m ||
                     ( url->uidvalidity() != 0 &&
                       m->uidvalidity() != url->uidvalidity() ) )
                {
                    setError( "invalid URL", url->orig() );
                    d->owner->execute();
                    return;
                }

                Permissions * p = d->checker->permissions( m, user );
                if ( !p )
                    p = new Permissions( m, user, this );
                d->checker->require( p, Permissions::Read );
                it->permissions = p;
                it->mailbox = m;
            }
            ++it;
        }

        d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->checker->ready() )
            return;

        if ( !d->checker->allowed() ) {
            List<UrlLink>::Iterator it( d->urls );
            while ( it ) {
                if ( !it->permissions->allowed( Permissions::Read ) ) {
                    setError( "invalid URL", it->url->orig() );
                    d->owner->execute();
                    return;
                }
                ++it;
            }
            d->owner->execute();
            return;
        }

        List<UrlLink>::Iterator it( d->urls );
        while ( it ) {
            if ( !it->url->urlauth().isEmpty() ) {
                it->q = new Query( "select key from access_keys where "
                                   "userid=$1 and mailbox=$2", this );
                it->q->bind( 1, it->url->user()->id() );
                it->q->bind( 2, it->mailbox->id() );
                it->q->execute();
            }
            ++it;
        }

        d->state = 3;
    }

    if ( d->state == 3 ) {
        d->fetchers = new List<Fetcher>;

        List<MailboxSet> sets;

        List<UrlLink>::Iterator it( d->urls );
        while ( it ) {
            ImapUrl * url = it->url;

            if ( it->q ) {
                if ( !it->q->done() )
                    return;

                Row * r = it->q->nextRow();
                if ( it->q->failed() || !r ) {
                    setError( "invalid URL", url->orig() );
                    d->owner->execute();
                    return;
                }

                EString rump( url->rump() );
                EString urlauth( url->urlauth() );
                EString key( r->getEString( "key" ).de64() );

                if ( urlauth != "0" + MD5::HMAC( key, rump ).hex() ) {
                    setError( "invalid URL", url->orig() );
                    d->owner->execute();
                    return;
                }

                Date * exp = url->expires();
                if ( exp ) {
                    Date now;
                    now.setCurrentTime();
                    if ( now.unixTime() > exp->unixTime() ) {
                        setError( "invalid URL", url->orig() );
                        d->owner->execute();
                        return;
                    }
                }
            }

            EString section( url->section() );
            if ( !section.isEmpty() ) {
                ImapParser * ip = new ImapParser( section );
                it->section = Fetch::parseSection( ip );
                ip->end();
                if ( !ip->ok() ) {
                    setError( "invalid URL", url->orig() );
                    d->owner->execute();
                    return;
                }
            }

            uint uid = url->uid();

            if ( !it->section ||
                 it->section->needsHeader ||
                 it->section->needsBody ) {
                MailboxSet * s = 0;
                List<MailboxSet>::Iterator ms( sets );
                while ( ms ) {
                    if ( ms->mailbox->id() == it->mailbox->id() ) {
                        s = ms;
                        break;
                    }
                    ++ms;
                }

                if ( !s ) {
                    s = new MailboxSet( it->mailbox );
                    sets.append( s );
                }

                if ( !it->section || it->section->needsHeader )
                    s->h.add( uid, uid );
                if ( !it->section || it->section->needsBody )
                    s->b.add( uid, uid );
            }

            ++it;
        }

        d->state = 4;

        List<Message> * al = new List<Message>;
        List<Message> * hl = new List<Message>;
        List<Message> * bl = 0;
        bool h = true;
        bool needIds = false;
        while ( !bl ) {
            if ( !h )
                bl = new List<Message>;
            List<MailboxSet>::Iterator ms( sets );
            while ( ms ) {
                IntegerSet s;
                if ( h )
                    s = ms->h;
                else
                    s = ms->b;
                while ( !s.isEmpty() ) {
                    uint uid = s.smallest();
                    s.remove( uid );
                    Message * m = MessageCache::provide( ms->mailbox, uid );
                    if ( !m->databaseId() ) {
                        ms->i.add( uid );
                        needIds = true;
                    }
                    if ( h ) {
                        if ( !m->hasHeaders() )
                            hl->append( m );
                        if ( !m->hasAddresses() )
                            al->append( m );
                    }
                    else {
                        if ( m->hasBodies() )
                            bl->append( m );
                    }
                    List<UrlLink>::Iterator it( d->urls );
                    while ( it ) {
                        if ( it->mailbox == ms->mailbox &&
                             it->url->uid() == uid )
                            it->message = m;
                        ++it;
                    }
                }
                ++ms;
            }
            h = false;
        }
        if ( !al->isEmpty() ) {
            Fetcher * f = new Fetcher( al, this, 0 );
            f->fetch( Fetcher::Addresses );
            d->fetchers->append( f );
        }
        if ( !hl->isEmpty() ) {
            Fetcher * f = new Fetcher( al, this, 0 );
            f->fetch( Fetcher::OtherHeader );
            d->fetchers->append( f );
        }
        if ( !bl->isEmpty() ) {
            Fetcher * f = new Fetcher( al, this, 0 );
            f->fetch( Fetcher::Body );
            d->fetchers->append( f );
        }
        if ( needIds ) {
            uint n = 1;
            d->findIds = new Query( "", this );
            EString a = "select mailbox, uid, message "
                       "from mailbox_messages where ";
            bool first = true;
            List<MailboxSet>::Iterator it( sets );
            while ( it ) {
                if ( !it->i.isEmpty() ) {
                    if ( !first )
                        a.append( " or " );
                    first = false;
                    a.append( "(mailbox=$" );
                    a.appendNumber( n );
                    d->findIds->bind( n, it->mailbox->id() );
                    n++;
                    a.append( " and uid=any($" );
                    a.appendNumber( n );
                    d->findIds->bind( n, it->i );
                    n++;
                    a.append( "))" );
                }
                ++it;
            }
            d->findIds->setString( a );
            d->findIds->execute();
        }
        else {
            List<Fetcher>::Iterator f( d->fetchers );
            while ( f ) {
                f->execute();
                ++f;
            }
        }
    }

    if ( d->state == 4 ) {
        if ( d->findIds ) {
            while ( d->findIds->hasResults() ) {
                Row * r = d->findIds->nextRow();
                Mailbox * mailbox = Mailbox::find( r->getInt( "mailbox" ) );
                uint uid = r->getInt( "uid" );
                uint id = r->getInt( "message" );
                List<UrlLink>::Iterator it( d->urls );
                while ( it ) {
                    if ( it->mailbox == mailbox &&
                         it->url->uid() == uid &&
                         it->message )
                        it->message->setDatabaseId( id );
                    ++it;
                }
            }
            if ( !d->findIds->done() )
                return;
            d->findIds = 0;
            List<Fetcher>::Iterator f( d->fetchers );
            while ( f ) {
                f->execute();
                ++f;
            }
        }

        List<Fetcher>::Iterator f( d->fetchers );
        while ( f ) {
            if ( !f->done() )
                return;
            ++f;
        }

        List<UrlLink>::Iterator it( d->urls );
        while ( it ) {
            if ( !it->message ) {
                setError( "invalid URL", it->url->orig() );
                d->owner->execute();
                return;
            }
            else if ( it->section ) {
                it->url->setText( Fetch::sectionData( it->section,
                                                      it->message ) );
            }
            else {
                it->url->setText( it->message->rfc822() );
            }

            ++it;
        }

        d->state = 5;
    }

    if ( d->state == 5 ) {
        d->state = 6;
        d->done = true;
        d->owner->execute();
    }
}


/*! Returns true only if this object has finished retrieving the text
    for the ImapUrls it was given; and false if it's still working.
*/

bool ImapUrlFetcher::done() const
{
    return d->done;
}


/*! Returns true only if this object encountered an error in trying to
    retrieve the text for the ImapUrls it was given, and false if the
    attempt is still in progress, or completed successfully. If this
    function returns true, badUrl() and error() describe the problem.
*/

bool ImapUrlFetcher::failed() const
{
    return !d->error.isEmpty();
}


/*! Returns the ImapUrl (in EString form) that caused the error(). This
    function is meaningful only when failed() is true, and it is meant
    to set the BADURL resp-text-code.
*/

EString ImapUrlFetcher::badUrl() const
{
    return d->badUrl;
}


/*! Returns a message describing why this object failed(), or an empty
    string if it's still working, or completed successfully.
*/

EString ImapUrlFetcher::error() const
{
    return d->error;
}


/*! Records the given error \a msg for the \a url. After the first call,
    done() and failed() will return true, error() will return \a msg,
    and badUrl() will return \a url. Subsequent calls are ignored.
*/

void ImapUrlFetcher::setError( const EString & msg, const EString & url )
{
    if ( d->error.isEmpty() ) {
        d->done = true;
        d->error = msg;
        d->badUrl = url;
    }
}
