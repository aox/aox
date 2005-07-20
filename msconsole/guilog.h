// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GUILOG_H
#define GUILOG_H

#include "logger.h"


class LogPane;


class GuiLog: public Logger
{
public:
    GuiLog();
    void send( const String &,
               Log::Facility, Log::Severity,
               const String & );
    void commit( const String &, Log::Severity );

    static void setLogPane( LogPane * );
    static LogPane * logPane();
};

#endif
