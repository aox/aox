#ifndef GUILOG_H
#define GUILOG_H

#include "logger.h"


class GuiLog: public Logger
{
public:
    GuiLog();
    void send( const String & ) {}
};

#endif
