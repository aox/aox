// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGGER_H
#define LOGGER_H

class String;


class Logger {
public:
    Logger();
    virtual void send( const String & ) = 0;
    virtual ~Logger();

    static Logger *global();
};


#endif
