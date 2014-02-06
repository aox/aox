// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef FETCHER_H
#define FETCHER_H

#include "event.h"
#include "list.h"


class Row;
class Query;
class Message;
class Mailbox;
class Connection;
class IntegerSet;
class PreparedStatement;


class Fetcher
    : public EventHandler
{
public:
    Fetcher( List<Message> *, EventHandler *, Connection * );

    Fetcher( Message *, EventHandler * );

    enum Type {
        Addresses,
        OtherHeader,
        Body,
        PartNumbers,
        Trivia
    };

    void addMessage( Message * );
    void addMessages( List<Message> * );

    void fetch( Type );
    bool fetching( Type ) const;

    void execute();

    bool done() const;

    void setTransaction( class Transaction * );

private:
    class FetcherData * d;

private:
    void start();
    void prepareBatch();
    void makeQueries();
    void waitForEnd();
    void submit( Query * );
    void bindIds( Query *, uint, Type );
};


#endif
