#ifndef INJECTOR_H
#define INJECTOR_H

#include "header.h"
#include "event.h"
#include "list.h"

class Message;
class Mailbox;


class Injector
    : public EventHandler
{
public:
    Injector( const Message *, List< Mailbox > *, EventHandler * );
    virtual ~Injector();

    void execute();

    bool done() const;
    bool failed() const;
    
private:
    class InjectorData *d;

    void addAddresses();
    void addAddresses( HeaderField::Type );
};


#endif
