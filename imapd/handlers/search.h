#ifndef SEARCH_H
#define SEARCH_H

#include "command.h"
#include "squery.h"


class Search
    : public Command
{
public:
    Search( bool u );

    void parse();
    void execute();

private:
    void parseKey( bool alsoCharset = false );

private:
    NotQuery::Condition * add( NotQuery::Field, NotQuery::Action,
                            const String & = 0, const String & = 0 );
    NotQuery::Condition * add( NotQuery::Field, NotQuery::Action, uint );
    NotQuery::Condition * add( const MessageSet & );

    NotQuery::Condition * push( NotQuery::Action );
    void pop();

    void prepare();

    String date();

private:
    class SearchD * d;
};


#endif
