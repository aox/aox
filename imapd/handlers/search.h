#ifndef __SEARCH_H__
#define __SEARCH_H__

#include "command.h"
#include "query.h"


class Search: public Command {
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
