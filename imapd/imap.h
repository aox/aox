#ifndef _IMAP_H_
#define _IMAP_H_

#include <mysql.h>
#include <mysqld_error.h>
#include <sys/types.h>

#include "misc.h"
#include "arena.h"
#include "array.h"
#include "config.h"
#include "tokens.h"

extern MYSQL *DB;
extern arena *global_arena;

enum RESULTS { OK, NO, BAD };
enum STATES  { UNAUTH = 1, AUTHED = 2, SELECTED = 4 };

/* A set of nonexistent UIDs: start <= uid < start+length. */
typedef struct {
    unsigned int start, length;
} hole;

/* this reflects the structure of the mailboxes table */
typedef struct {
    int id;
    const char *name;
    unsigned int messages, recent;
    unsigned int uidmax, uidvalidity;   /* u_int32_t ? */
    unsigned int nholes;
    hole *holes;
} mailbox;

/* a single request-response exchange */
typedef struct {
    char *tag;
    char *command;
    int uidcmd;
    char *arg;
    int result;                 /* OK, NO, BAD */
    char *status;
} interaction;

typedef struct {
    int ro;
    mailbox *m;
} session;

typedef struct {
    unsigned int id;
    char *name;
} user;

/* XXX: We need to free all of this stuff. */
typedef struct {
    int state;                  /* UNAUTH, AUTHED, SELECTED */
    user *u;                    /* Information about the current user. */
    config *config;             /* server configuration information */
    session *s;                 /* NULL unless state == SELECTED */
} connection;

#endif
