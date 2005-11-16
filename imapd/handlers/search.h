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
    virtual void process();

protected:
    void setCharset( const String & );
    void parseKey( bool alsoCharset = false );
    void prepare();

    Selector * selector() const;

private:
    void push( Selector::Action );
    void add( Selector * );
    void pop();

    String debugString();

    String date();

    void considerCache();

    UString ustring( Command::QuoteMode stringType );

private:
    class SearchData * d;
    friend class SearchData;
};


#endif
