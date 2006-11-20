// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SEARCH_H
#define SEARCH_H

#include "command.h"
#include "messageset.h"
#include "selector.h"
#include "ustring.h"


class Message;


class Search
    : public Command
{
public:
    Search( bool u );

    void parse();
    void execute();

protected:
    void setCharset( const String & );
    void parseKey( bool alsoCharset = false );

    Selector * selector() const;

    void sendSearchResponse();
    void sendEsearchResponse();
    void sendResponse();

private:
    void push( Selector::Action );
    void add( Selector * );
    void pop();

    String date();

    void considerCache();

    UString ustring( Command::QuoteMode stringType );

    MessageSet set( bool );

private:
    class SearchData * d;
    friend class SearchData;
};


#endif
