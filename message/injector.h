#ifndef INJECTOR_H
#define INJECTOR_H

#include "event.h"
#include "header.h"


class Message;
class Mailbox;


class Injector: public EventHandler
{
public:
    Injector( const Message *, List<Mailbox> *, EventHandler * );

    void execute();

    bool done() const;
    bool failed() const;

private:
    void addAddresses( HeaderField::Type );
    void addAddresses();
    String addressQuery() const;
    String bodypartQuery() const;
    String messageQuery() const;

private:
    class InjectorData * d;
};


#endif
