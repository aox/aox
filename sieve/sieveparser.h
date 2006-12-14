// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEPARSER_H
#define SIEVEPARSER_H

#include "abnfparser.h"

#include "list.h"


class SieveParser
    : public AbnfParser
{
public:
    SieveParser( const String & );

    // productions in RFC3028bis section 8.1

    void bracketComment();
    void comment();
    void hashComment();

    String identifier();

    String multiLine();

    uint number();

    String quotedString();

    String tag();

    void whitespace();

    // productions in RFC3028bis section 8.2

    String addressPart();

    class SieveArgument * argument();

    class SieveArgumentList * arguments();

    class SieveBlock * block();

    // conflict with sievecommand.h
    class SieveCommand * command();

    List<class SieveCommand> * commands();

    String comparator();

    String matchType();

    String string();

    class StringList * stringList();

    class SieveTest * test();

    class SieveTestList * testList();
};


#endif
