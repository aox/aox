#ifndef STORE_H
#define STORE_H

#include "command.h"


class Store
    : public Command
{
public:
    Store( bool u );

    void parse();
    void execute();

private:
    class StoreData * d;

private:
    bool addExtraFlagNames();
    void splitSystemExtra();
    void updateSystemFlags();
    void killSuperfluousRows();
    void addExtraFlags();
    void pretendToFetch();
    void sendFetches();
    bool dumpFetchResponses();
};


#endif
