#ifndef USER_H
#define USER_H

class Query;
class String;
class EventHandler;


class User {
public:
    static Query *create( const String &, const String &, EventHandler * );
};


#endif
