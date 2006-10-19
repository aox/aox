// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapurlfetcher.h"


class IufData
    : public Garbage
{
public:
    IufData()
        : state( 0 ), done( false ), urls( 0 ), owner( 0 )
    {}

    int state;
    bool done;
    String error;
    String badUrl;
    List<ImapUrl> * urls;
    EventHandler * owner;
};


/*! \class ImapUrlFetcher imapurlfetcher.h
    Returns the texts referenced by a List of IMAP URLs.

    This class takes a list of ImapUrls and retrieves the corresponding
    text from the database, subject to validation and access control. It
    is the basis for our CATENATE/URLFETCH/BURL support.

    For each submitted URL, this class does the following:

    1. Verify that the ImapUrl::user() is valid.
    2. Verify that the ImapUrl::mailboxName() refers to an existing
       mailbox in the relevant user's namespace.
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
    d->urls = l;
    d->owner = ev;
}


void ImapUrlFetcher::execute()
{
    if ( d->state == 0 ) {
        if ( d->urls->isEmpty() ) {
            d->done = true;
            return;
        }
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


/*! Returns the ImapUrl (in String form) that caused the error(). This
    function is meaningful only when failed() is true, and it is meant
    to set the BADURL resp-text-code.
*/

String ImapUrlFetcher::badUrl() const
{
    return d->badUrl;
}


/*! Returns a message describing why this object failed(), or an empty
    string if it's still working, or completed successfully.
*/

String ImapUrlFetcher::error() const
{
    return d->error;
}


/*! Records the given error \a msg for the \a url. After the first call,
    done() and failed() will return true, error() will return \a msg,
    and badUrl() will return \a url. Subsequent calls are ignored.
*/

void ImapUrlFetcher::setError( const String & msg, const String & url )
{
    if ( d->error.isEmpty() ) {
        d->done = true;
        d->error = msg;
        d->badUrl = url;
    }
}
