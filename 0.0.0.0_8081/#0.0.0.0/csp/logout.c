#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
//  xbuf_t *reply = get_reply ( argv );

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }
  
  char *uid;
  int auth = is_member(argv, data, &uid);

  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }
LINE_

  char *old_auth;
LINE_
  char *username = NULL;
LINE_
  redisReply *rr;
LINE_
  xbuf_t *cookie_buf;
LINE_
  xbuf_t *tmp_xbuf;
  redisContext *rc = data->rc[cur_worker()];
  static char auth_deleted[] =
    "Set-Cookie:auth=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; httponly\r\n"
    "Location:/\r\n\r\n";

  rr = redisCommand(rc, "HGET uid:%s username", uid);
LINE_
  if(rr == NULL) return 503; // service unavailable
  if(rr->type == REDIS_REPLY_NIL){
LINE_
    freeReplyObject(rr);
    return 500; // internal server error
  }
  username = strndup(rr->str, rr->len);
  freeReplyObject(rr);
LINE_

  tmp_xbuf = gw_gen_cookie_header(username, &cookie_buf);
LINE_

  rr = redisCommand(rc, "SET auth:%s %s", cookie_buf->ptr, uid);
  freeReplyObject(rr);
LINE_

  rr = redisCommand(rc, "HSET uid:%s auth %s", uid, cookie_buf->ptr);
  freeReplyObject(rr);
LINE_

LINE_
  old_auth = gw_cookie(argv, "auth=", 5);

LINE_
  rr = redisCommand(rc, "DEL auth:%s", old_auth);
  freeReplyObject(rr);

LINE_
  free(uid);
  free(old_auth);
  free(username);
LINE_
  xbuf_free(tmp_xbuf);
  xbuf_free(cookie_buf);

LINE_
  http_header(HEAD_ADD, auth_deleted, sizeof(auth_deleted), argv);

LINE_
  return 302;
}
