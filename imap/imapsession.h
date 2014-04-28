// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "imapresponse.h"
#include "estringlist.h"
#include "session.h"
#include "list.h"

class IntegerSet;
class Mailbox;
class Message;
class IMAP;


class ImapSession
    : public Session
{
public:
    ImapSession( IMAP *, Mailbox *, bool, bool = false );
    ~ImapSession();

    IMAP * imap() const;

    void emitUpdates( Transaction * t );

    void recordExpungedFetch( const IntegerSet & );

    void ignoreModSeq( int64 );

    void clearExpunged( uint );

    void sendFlagUpdate();
    void sendFlagUpdate( class FlagCreator * );

    bool unicode() const;

private:
    class ImapSessionData * d;

    void emitFlagUpdates( Transaction * );
};


class ImapExpungeResponse
    : public ImapResponse
{
public:
    ImapExpungeResponse( uint, ImapSession * );

    EString text() const;
    void setSent();

private:
    uint u;
};


class ImapVanishedResponse
    : public ImapResponse
{
public:
    ImapVanishedResponse( const IntegerSet &, ImapSession * );

    EString text() const;
    void setSent();

private:
    IntegerSet * s;
};


#endif
