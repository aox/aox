#ifndef SEARCH_H
#define SEARCH_H

#include "imapcommand.h"
#include "squery.h"


class Search
    : public ImapCommand
{
public:
    Search( bool u );

    void parse();
    void execute();

private:
    void parseKey( bool alsoCharset = false );

private:
    Query::Condition * add( Query::Field, Query::Action,
                            const String & = 0, const String & = 0 );
    Query::Condition * add( Query::Field, Query::Action, uint );
    Query::Condition * add( const Set & );

    Query::Condition * push( Query::Action );
    void pop();

    void prepare();

    String date();

private:
    class SearchD * d;
};


#endif
