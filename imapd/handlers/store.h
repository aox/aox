// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STORE_H
#define STORE_H

class Flag;
class Query;
class Mailbox;

#include "command.h"


class Store
    : public Command
{
public:
    Store( bool u );

    void parse();
    void execute();

    static Query * addFlagsQuery( Flag * f, Mailbox * m,
                                  const MessageSet & s, EventHandler * h );

private:
    class StoreData * d;

private:
    bool processFlagNames();
    void removeFlags( bool opposite = false );
    void addFlags();
    void replaceFlags();
    void recordFlags();
    void pretendToFetch();
    void sendFetches();
    bool dumpFetchResponses();
};


#endif
