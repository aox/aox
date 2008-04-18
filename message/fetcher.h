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

    enum Type {
        Flags,
        Annotations,
        Addresses,
        OtherHeader,
        Body,
        Trivia
    };

    void addMessages( List<Message> * );

    void fetch( Type );
    bool fetching( Type ) const;

    void execute();

    bool done() const;

private:
    class FetcherData * d;
};


class MessageFetcher
    : public EventHandler
{
public:
    MessageFetcher( uint, EventHandler * );

    Message * message() const;

    void execute();

private:
    class MessageFetcherData * d;
};


#endif
