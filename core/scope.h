// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCOPE_H
#define SCOPE_H

class Log;


class Scope {
public:
    Scope();
    Scope( Log * );
    ~Scope();

    static Scope *current();

    Log *log() const;
    void setLog( Log * );

private:
    Scope *parent;
    Log   *currentLog;
};


#endif
