// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPURL_H
#define IMAPURL_H

#include "global.h"
#include "string.h"


class IMAP;


class ImapUrl
    : public Garbage
{
public:
    ImapUrl( const String & );
    ImapUrl( const IMAP *, const String & );

    bool valid() const;

    String mailbox() const;
    uint uid() const;
    String section() const;

private:
    class ImapUrlData * d;

    void parse( const String & );
    bool stepOver( const String & );
    bool unreserved( char );
    bool escape( char * );
    bool number( uint * );
    String xchars( bool = false );
    bool hostport();
};


#endif
