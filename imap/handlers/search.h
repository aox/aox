// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SEARCH_H
#define SEARCH_H

#include "command.h"
#include "integerset.h"
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
    void setCharset( const EString & );
    Selector * parseKey();

    Selector * selector() const;

    void sendResponse();

private:
    EString date();

    void considerCache();

    UString ustring( Command::QuoteMode stringType );

    IntegerSet set( bool );

private:
    class SearchData * d;
    friend class SearchData;
};


class ImapSearchResponse
    : public ImapResponse
{
public:
    ImapSearchResponse( ImapSession *, const IntegerSet &,
                        int64, const EString & tag,
                        bool,
                        bool, bool, bool, bool );
    EString text() const;

private:
    IntegerSet r;
    int64 ms;
    EString t;
    bool uid, min, max, count, all;
};


#endif
