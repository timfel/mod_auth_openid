/*
Copyright (C) 2007-2010 Butterfat, LLC (http://butterfat.net)

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Created by bmuller <bmuller@butterfat.net>
*/

#include "mod_auth_openid.h"

namespace modauthopenid {
  using namespace std;

  SessionManager::SessionManager(const string& storage_location) {
    is_closed = false;
    int rc = sqlite3_open(storage_location.c_str(), &db);
    if(!test_result(rc, "problem opening database"))
      return;
    sqlite3_busy_timeout(db, 5000);
    string query = "CREATE TABLE IF NOT EXISTS sessionmanager "
      "(id INTEGER PRIMARY KEY, session_id VARCHAR(33), hostname VARCHAR(255), path VARCHAR(255), identity VARCHAR(255), expires_on INT)";
    rc = sqlite3_exec(db, query.c_str(), 0, 0, 0);
    test_result(rc, "problem creating table if it didn't exist already");

    rc = sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS session_id_index ON sessionmanager (session_id)", 0, 0, 0);
    test_result(rc, "problem creating index if it didn't exist already");
    rc = sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS expires_on_index ON sessionmanager (expires_on)", 0, 0, 0);
    test_result(rc, "problem creating index if it didn't exist already");

    query = "CREATE TABLE IF NOT EXISTS env_vars "
      "(sess_id INTEGER, expires_on INTEGER, key VARCHAR(25), value TEXT)";
    rc = sqlite3_exec(db, query.c_str(), 0, 0, 0);
    test_result(rc, "problem creating table if it didn't exist already");

    rc = sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS sess_id_index ON env_vars (sess_id)", 0, 0, 0);
    test_result(rc, "problem creating index if it didn't exist already");
    rc = sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS expires_on_index ON env_vars (expires_on)", 0, 0, 0);
    test_result(rc, "problem creating index if it didn't exist already");
  };

  void SessionManager::get_session(const string& session_id, session_t& session) {
    ween_expired();
    const char *q1 = "SELECT session_id,hostname,path,identity,expires_on FROM sessionmanager WHERE session_id=%Q LIMIT 1";
    char *sql = sqlite3_mprintf(q1, session_id.c_str());
    int nr, nc;
    char **table;
    int rc = sqlite3_get_table(db, sql, &table, &nr, &nc, 0);
    sqlite3_free(sql);
    test_result(rc, "problem fetching session with id " + session_id);
    if(nr==0) {
      session.identity = "";
      debug("could not find session id " + session_id + " in db: session probably just expired");
    } else {
      session.session_id = string(table[5]);
      session.hostname = string(table[6]);
      session.path = string(table[7]);
      session.identity = string(table[8]);
      session.expires_on = strtol(table[9], 0, 0);
    }
    sqlite3_free_table(table);

    const char *q2 = "SELECT e.key, e.value FROM env_vars as e, sessionmanager as s WHERE e.sess_id=s.id AND s.session_id=%Q";
    sql = sqlite3_mprintf(q2, session_id.c_str());
    debug(sql);
    rc = sqlite3_get_table(db, sql, &table, &nr, &nc, 0);
    sqlite3_free(sql);
    test_result(rc, "problem fetching env_vars for id " + session_id);
    for(int i=0; i<nr; ++i) {
      session.env_vars[string(table[(i+1)*2])] = string(table[(i+1)*2 + 1]);
    }
    sqlite3_free_table(table);
  };

  bool SessionManager::test_result(int result, const string& context) {
    if(result != SQLITE_OK){
      string msg = "SQLite Error in Session Manager - " + context + ": %s\n";
      fprintf(stderr, msg.c_str(), sqlite3_errmsg(db));
      sqlite3_close(db);
      is_closed = true;
      return false;
    }
    return true;
  };

  void SessionManager::store_session(const string& session_id, const string& hostname, const string& path, const string& identity, const map<string,string>& env_vars, int lifespan) {
    ween_expired();
    time_t rawtime;
    time (&rawtime);

    // lifespan will be 0 if not specified by user in config - so lasts as long as browser is open.  In this case, make it last for up to a day.
    int expires_on = (lifespan == 0) ? (rawtime + 86400) : (rawtime + lifespan);

    const char* q1 = "INSERT INTO sessionmanager (session_id,hostname,path,identity,expires_on) VALUES(%Q,%Q,%Q,%Q,%d)";
    char *query = sqlite3_mprintf(q1, session_id.c_str(), hostname.c_str(), path.c_str(), identity.c_str(), expires_on);
    debug(query);
    int rc = sqlite3_exec(db, query, 0, 0, 0);
    sqlite3_free(query);
    test_result(rc, "problem inserting session into db");

    sqlite3_int64 sess_id = sqlite3_last_insert_rowid(db);
    for(map<string,string>::const_iterator it = env_vars.begin(); it != env_vars.end(); ++it) {
      std::string key = it->first;
      std::string val = it->second;

      const char* q2 = "INSERT INTO env_vars (sess_id,expires_on,key,value) VALUES(%lld,%d,%Q,%Q)";
      char *query = sqlite3_mprintf(q2, sess_id, expires_on, key.c_str(), val.c_str() );
      debug(query);
      int rc = sqlite3_exec(db, query, 0, 0, 0);
      sqlite3_free(query);
      test_result(rc, "problem inserting env_vars into db");
    }
  };

  void SessionManager::ween_expired() {
    time_t rawtime;
    time (&rawtime);
    char *query = sqlite3_mprintf("DELETE FROM sessionmanager WHERE %d > expires_on", rawtime);
    int rc = sqlite3_exec(db, query, 0, 0, 0);
    sqlite3_free(query);
    test_result(rc, "problem weening expired sessions from table");

    query = sqlite3_mprintf("DELETE FROM env_vars WHERE %d > expires_on", rawtime);
    rc = sqlite3_exec(db, query, 0, 0, 0);
    sqlite3_free(query);
    test_result(rc, "problem weening expired env_vars from table");
  };

  // This is a method to be used by a utility program, never the apache module                 
  void SessionManager::print_table() {
    ween_expired();
    print_sqlite_table(db, "sessionmanager");
  };

  void SessionManager::close() {
    if(is_closed)
      return;
    is_closed = true;
    test_result(sqlite3_close(db), "problem closing database");
  };
}
