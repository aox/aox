#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Fetch
    : public Command
{
public:
    Fetch( bool = false );

    void parse();
    void execute();

    void parseAttribute( bool alsoMacro );
    void parseBody();

    String dotLetters( uint, uint );

    String coreQuery() const;
    String headerQuery() const;
    String bodyQuery() const;

private:
    bool uid;
    class FetchData * d;
};


#endif
