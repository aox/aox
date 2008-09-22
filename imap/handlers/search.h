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
    Selector * parseKey();

    Selector * selector() const;

    void sendResponse();

private:
    String date();

    void considerCache();

    UString ustring( Command::QuoteMode stringType );

    MessageSet set( bool );

private:
    class SearchData * d;
    friend class SearchData;
};


class ImapSearchResponse
    : public ImapResponse
{
public:
    ImapSearchResponse( ImapSession *, const MessageSet &,
                        int64, const String & tag,
                        bool,
                        bool, bool, bool, bool );
    String text() const;

private:
    MessageSet r;
    int64 ms;
    String t;
    bool uid, min, max, count, all;
};


#endif
