#ifndef CACHE_H
#define CACHE_H


class CacheLookup {
public:
    CacheLookup();

    enum State { Executing, Completed };
    void setState( State );
    State state() const;
    bool done() const;

private:
    State st;
};


#endif
