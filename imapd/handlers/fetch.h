#ifndef __FETCH_H__
#define __FETCH_H__

#include "command.h"


class Fetch: public Command {
public:
    Fetch( bool u ): uid( u ) {}

    void parse();
    void execute();

    void parseAttribute( bool alsoMacro );
    void parseBody();

    String dotLetters( uint, uint );

private:
    bool uid;
    class FetchData * d;
};

#endif

