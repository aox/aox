#ifndef LOGGER_H
#define LOGGER_H

class String;

class Logger {
protected:
    Logger();
    virtual ~Logger();

public:
    virtual void send( const String & ) = 0;
    static Logger *logger();
};


#endif
