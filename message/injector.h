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
    Injector( const Message *, SortedList< Mailbox > *, EventHandler * );
    virtual ~Injector();

    bool done() const;
    bool failed() const;
    void execute();

private:
    class InjectorData *d;

    void selectUids();
    void buildAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertBodyparts();
    void insertMessages();
    void linkHeaderFields();
    void linkBodyparts();
    void linkAddresses();
};


#endif
