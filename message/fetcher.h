// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCHER_H
#define FETCHER_H

#include "event.h"
#include "list.h"


class Row;
class Query;
class Message;
class Mailbox;
class MessageSet;
class PreparedStatement;


class Fetcher
    : public EventHandler
{
public:
    Fetcher( Mailbox * );

    void execute();

    void insert( const MessageSet &, EventHandler * );

    virtual PreparedStatement * query() const = 0;
    virtual void decode( Message *, Row * ) = 0;
    virtual void setDone( Message * ) = 0;
    void setDone( uint );

private:
    class FetcherData * d;
};



class MessageHeaderFetcher
    : public Fetcher
{
public:
    MessageHeaderFetcher( Mailbox * m ): Fetcher( m ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageFlagFetcher
    : public Fetcher
{
public:
    MessageFlagFetcher( Mailbox * m ): Fetcher( m ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageBodyFetcher
    : public Fetcher
{
public:
    MessageBodyFetcher( Mailbox * m ): Fetcher( m ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageTriviaFetcher
    : public Fetcher
{
public:
    MessageTriviaFetcher( Mailbox * m ): Fetcher( m ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageAnnotationFetcher
    : public Fetcher
{
public:
    MessageAnnotationFetcher( Mailbox * m ): Fetcher( m ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


#endif
