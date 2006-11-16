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
    Fetcher( Mailbox *, List<Message> *, EventHandler * );

    void execute();

    virtual PreparedStatement * query() const = 0;
    virtual void decode( Message *, Row * ) = 0;
    virtual void setDone( Message * ) = 0;
    virtual void setDone( uint );

    bool done() const;

private:
    friend class MessageAddressFetcher; // XXX remove when MOAF dies
    class FetcherData * d;
};



class MessageHeaderFetcher
    : public Fetcher
{
public:
    MessageHeaderFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageAddressFetcher
    : public Fetcher
{
public:
    MessageAddressFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );

    void execute();

private:
    List<class AddressField> l;
    List<Message> fallbackNeeded;
};


class MessageOldAddressFetcher
    : public MessageHeaderFetcher
{
public:
    MessageOldAddressFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : MessageHeaderFetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void setDone( Message * );
};


class MessageFlagFetcher
    : public Fetcher
{
public:
    MessageFlagFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageBodyFetcher
    : public Fetcher
{
public:
    MessageBodyFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageTriviaFetcher
    : public Fetcher
{
public:
    MessageTriviaFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );
};


class MessageAnnotationFetcher
    : public Fetcher
{
public:
    MessageAnnotationFetcher( Mailbox * m, List<Message> * s, EventHandler * e )
        : Fetcher( m, s, e ) {}

    PreparedStatement * query() const;
    void decode( Message *, Row * );
    void setDone( Message * );

private:
    class AnnotationNameFetcher * f;
};


#endif
