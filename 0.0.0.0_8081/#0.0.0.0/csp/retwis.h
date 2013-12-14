#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include <hiredis/hiredis.h>
#include "gwan.h"

#define LINE_ printf("{%s}{%d}\n", __func__, __LINE__);

#define cur_worker() \
  (int) get_env( argv, CUR_WORKER )

#define BASE_HTML \
 "<!doctype html><html><head>" \
 "<title><!--title--></title></head>" \
 "<body><!--content--></body></html>"

#define REGISTER_FORM \
 "<!--form_errors-->" \
 "<form action=\"/?register\" method=\"POST\">" \
 "Username: <input type=\"text\" name=\"username\"/><br/>" \
 "Password: <input type=\"password\" name=\"password\"/><br/>" \
 "Password(repeat): <input type=\"password\" name=\"password_verify\"/><br/>" \
 "<input type=\"submit\" name=\"submit\" value=\"Register / LoginNow\"/>" \
 "</form>"

#define LOGIN_FORM \
 "<!--form_errors-->" \
 "<form action=\"/?login\" method=\"POST\">" \
 "Username: <input type=\"text\" name=\"username\"/><br/>" \
 "Password: <input type=\"password\" name=\"password\"/><br/>" \
 "<input type=\"submit\" name=\"submit\" value=\"Login\"/>" \
 "</form>"


#define NEW_POST_FORM \
 "<!--form_errors-->" \
 "<form action='/?add_post' method='POST' class='span4'>" \
 "<textarea class='span4' name='post' rows='3' columns='33' placeholder='Share anything...'></textarea></br>" \
 "<button type='submit' name='submit' class='btn pull-right'>Share</button>" \
 "</form>" \
 "<div style='clear: both;'></div>"


/*
  EXAMPLE SERVLET

#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
  xbuf_t *reply = get_reply ( argv );

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }

  char *uid = NULL;
  int auth = is_member(argv, data, &uid);

//    YOUR CODE GOES HERE
  xbuf_xcat(reply, "Hello World!    auth: %d\n", auth);

  if(auth == true) free(uid);
  return 200;
}

*/

/*
  BASIC REDIRECT BASED ON AUTH:
  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }
*/

typedef struct data_st {
  redisContext **rc;
  xbuf_t *profile_page;
  xbuf_t *main_page;
  xbuf_t *register_page;
  xbuf_t *login_page;
  xbuf_t *followers_page;
  xbuf_t *followings_page;
} data_t;

#define RETARGS_ char *argv[], data_t *data // Retwis args used at function prototypes
#define RA_ argv, data // retwis args
#define ARGV_ char *argv[]

static inline int  init_data (char *argv[], data_t **Data);
static inline void destroy_data (data_t **Data);
xbuf_t *load_file_from_www (ARGV_, char *filename);
xbuf_t *load_file_from_csp (ARGV_, char *filename);
char *get_uid_from_username (RETARGS_, char *username);
static inline void auth_based_links (xbuf_t *xbuf, bool auth,
                                         bool is_at_homepage);
static inline char *gw_cookie (ARGV_, char *cookie_name
                                            , size_t cookie_len);
static inline bool is_member (RETARGS_, char **uid_dst);
int update_timeline (RETARGS_, char *whom);
xbuf_t *get_timeline (RETARGS_, char *uid, int from, int to);
xbuf_t *get_posts (RETARGS_, char *uid, int from, int to);
xbuf_t *get_posts_anonymous (RETARGS_, char *uid, int from, int to);
xbuf_t *get_posts_by_username (RETARGS_, char *username, int from, int to);
int add_post (RETARGS_, char *from, char *body, u64 *id_dst);
void del_post (RETARGS_, char *uid, u64 id);
int follow (RETARGS_, char *from, char *to);
int unfollow (RETARGS_, char *from, char *to);
bool is_following (RETARGS_, char *who, char *to_who);
char *get_username(RETARGS_, char *uid);
bool user_is_exists (RETARGS_, char *username);
bool get_from_to_args(int argc, char *argv[], int *from_dst, int *to_dst);
void next_prev_links(xbuf_t *reply, char *url_prefix, int from, int to);

static inline int init_data (char *argv[], data_t **Data)
{
  if(*Data != NULL) return 0;
  data_t *data;
  int nbr_workers = (int) get_env(argv, NBR_WORKERS);

  data = (data_t *) malloc(sizeof(data_t));
  if(!data) return -1;

  data->rc = (redisContext **) malloc(
     sizeof(redisContext *) * nbr_workers);
  for (int i=0; i < nbr_workers; i++)
  {
      data->rc[i] = redisConnect("127.0.0.1", 6379);
      if(data->rc[i]->err)
      {
        printf("ERROR! %s\n", data->rc[i]->errstr);
        free(data->rc);
        free(data);
        *Data = NULL;
        return -1;
      }
  }

  // load templates to ram
  data->main_page = load_file_from_www(argv, "main.page");
  if(!data->main_page) { destroy_data(Data); return -1; }

  data->profile_page = load_file_from_www(argv, "profile.page");
  if(!data->profile_page) { destroy_data(Data); return -1; }

  data->register_page = load_file_from_www(argv, "register.page");
  if(!data->register_page) { destroy_data(Data); return -1; }

  data->login_page = load_file_from_www(argv, "login.page");
  if(!data->profile_page) { destroy_data(Data); return -1; }

  data->followers_page = load_file_from_www(argv, "followers.page");
  if(!data->followers_page) { destroy_data(Data); return -1; }

  data->followings_page = load_file_from_www(argv, "followings.page");
  if(!data->followings_page) { destroy_data(Data); return -1; }

  *Data = data;
  return 0;
}

static inline void destroy_data (data_t **Data)
{
  data_t *data = *Data;
//  if(data->rc != NULL) free(data->rc);
  if(data->main_page) {
    xbuf_free(data->main_page);
    free(data->main_page);
  }
  if(data->profile_page) {
    xbuf_free(data->profile_page);
    free(data->profile_page);
  }
  if(data->register_page) {
    xbuf_free(data->register_page);
    free(data->register_page);
  }
  if(data->login_page) {
    xbuf_free(data->login_page);
    free(data->login_page);
  }
  free(data);
  *Data = NULL;
}

xbuf_t *load_file_from_www (char *argv[], char *filename)
{
  xbuf_t *out = malloc(sizeof(xbuf_t));
  if(out == NULL) return NULL;
  xbuf_init(out);
  char *wwwpath = (char*)get_env(argv, WWW_ROOT);
  char str[1024];
  s_snprintf(str, 1023, "%s/%s", wwwpath, filename);
  xbuf_frfile(out, str);
  if(out->len < 1)
  {
    xbuf_free(out);
    free(out);
    return NULL;
  }
  return out;
}

xbuf_t *load_file_from_csp (char *argv[], char *filename)
{
  xbuf_t *out = malloc(sizeof(xbuf_t));
  if(out == NULL) return NULL;
  xbuf_init(out);
  char *wwwpath = (char*)get_env(argv, WWW_ROOT);
  char str[1024];
  s_snprintf(str, 1023, "%s/%s", wwwpath, filename);
  xbuf_frfile(out, str);
  if(out->len < 1)
  {
    xbuf_free(out);
    free(out);
    return NULL;
  }
  return out;
}

char *get_uid_from_username (char *argv[], data_t *data, char *username)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "GET username:%s:uid", username);
  if(rr == NULL) return NULL;
  if(rr->type != REDIS_REPLY_STRING)
  {
    freeReplyObject(rr);
    return NULL;
  }
  char *uid = strndup(rr->str, rr->len);
  freeReplyObject(rr);
  return uid;
}

static inline void auth_based_links (xbuf_t *xbuf, bool auth, bool is_at_homepage)
{
  if(is_at_homepage == true)
  {
    if(auth != true)
      xbuf_repl(xbuf, "<!--login-logout-register-profile-links-->",
        "<li class='active'><a href='/'><i class='icon-home'></i> Home</a></li>"
        "<li><a href='/?login'><i class='icon-user'></i> Login</a></li>"
        "<li><a href='/?register'><i class='icon-arrow-right'></i> Register</a></li>");
    else
      xbuf_repl(xbuf, "<!--login-logout-register-profile-links-->",
        "<li class='active'><a href='/'><i class='icon-home'></i> Home</a></li>"
        "<li><a href='/?profile'><i class='icon-user'></i> Profile</a></li>"
        "<li><a href='/?logout'><i class='icon-minus'></i> Log Out</a></li>");
  }
  else // is_at_home == false
  {
    if(auth != true)
      xbuf_repl(xbuf, "<!--login-logout-register-profile-links-->",
        "<li><a href='/'><i class='icon-home'></i> Home</a></li>"
        "<li><a href='/?login'><i class='icon-user'></i> Login</a></li>"
        "<li><a href='/?register'><i class='icon-arrow-right'></i> Register</a></li>");
    else
      xbuf_repl(xbuf, "<!--login-logout-register-profile-links-->",
        "<li><a href='/'><i class='icon-home'></i> Home</a></li>"
        "<li class='active'><a href='/?profile'><i class='icon-user'></i> Profile</a></li>"
        "<li><a href='/?logout'><i class='icon-minus'></i> Log Out</a></li>");
  }
}

static inline char *gw_cookie (char *argv[], char *cookie_name
               , size_t cookie_len)
{
  http_t *http = (http_t*)get_env(argv, HTTP_HEADERS);
  xbuf_t *read_buf  = (xbuf_t*)get_env(argv, READ_XBUF);
  char *p = read_buf->ptr;
  char *cookies = http->h_cookies ? p + http->h_cookies : 0;

  if(cookies != 0)
  {
    char *cookie = strstr(cookies, cookie_name);
    if(cookie != 0)
    {

      char *val = strchr(cookie, ' ');
      size_t len = strlen(&cookie[cookie_len + 2]);

      if(len > 1 && val == 0) val = strdup(&cookie[cookie_len]);
      if(val != 0)
      {
        if(val[len] == ';') val[len] = '\0';
        return val;
      }

    }
  }

  return NULL;
}

static inline bool is_member (char *argv[], data_t *data, char **uid_dst)
{
  char *auth = gw_cookie(argv, "auth=", 5);
  if (!auth)  return false;

  redisReply *rr = redisCommand(data->rc[cur_worker()], "GET auth:%s", auth);
  free(auth);

  if(rr != NULL && rr->len)
  { // User is member
    if(uid_dst) *uid_dst = strndup(rr->str, rr->len);
    freeReplyObject(rr);
    return true;
  }

  freeReplyObject(rr);
  return false;
}

int update_timeline (char *argv[], data_t *data, char *whom)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;

  rr = redisCommand(rc, "DEL uid:%s:timeline", whom);
  if (rr == NULL) return -1;
  freeReplyObject(rr);

  rr = redisCommand(rc,
     "LRANGE global:timeline 0 -1");
  if (rr == NULL) return -1;

  for(int i = 0; i < rr->elements; i++)
  {
    redisReply *rr2 = redisCommand(rc, "HMGET post:%s uid", 
      rr->element[i]->str);

    if (rr2 == NULL) return -1;

    { // if currrent user following this user, add this post to
      // his/her timeline
      redisReply *rr3 = redisCommand(rc,
        "SISMEMBER uid:%s:following %s", whom, rr2->element[0]->str);
      if (rr3 == NULL) return -1;
      if (rr3->integer == 1)
      { // add this post to current user's timeline
        redisReply *rr4 = redisCommand(rc,
          "RPUSH uid:%s:timeline %s", whom, rr->element[i]->str);
        if (rr4 == NULL) return -1;
        freeReplyObject(rr4);
      }
      freeReplyObject(rr3);
    }
    freeReplyObject(rr2);
  }
  freeReplyObject(rr);
  return 0;
}

u64 nextUserId (char *argv[], data_t *data)
{
  u64 id = 0;
LINE_
  redisReply *rr = redisCommand(data->rc[cur_worker()],
     "INCR global:nextUserId");
LINE_
  if (rr == NULL) return 0; // fail
  id = rr->integer;
LINE_
  freeReplyObject(rr);
LINE_
  return id;
}

u64 nextPostId (char *argv[], data_t *data)
{
  u64 id = 0;
  redisReply *rr = redisCommand(data->rc[cur_worker()],
     "INCR global:nextPostId");
  if (rr == NULL) return 0; // fail
  id = rr->integer;
  freeReplyObject(rr);
  return id;
}

xbuf_t *to_sha2 (char *input)
{
LINE_
  u8 result[32];
  xbuf_t *xbuf = (xbuf_t *) malloc(sizeof(xbuf_t));
LINE_
  xbuf_init (xbuf); // important!
LINE_
  if(!xbuf) return NULL;
LINE_
  sha2((u8 *)input, strlen((const char *)input), result);
LINE_
  xbuf_xcat(xbuf, "%32B", result);
LINE_
  return xbuf;
}

xbuf_t *gw_gen_cookie(char *input)
{
  xbuf_t *out = to_sha2(input);
  static char c[] = "fatihky274zXc6vMT98bnQwWrt"; // 21 chars
  xbuf_growto(out, 10);

  prnd_t rnd;

  sw_init(&rnd, time(0)); // pseudo-random numbers generator 

  for(int i = 0; i < 10; i++)
  {
    xbuf_ncat(out, &c[sw_rand(&rnd) % 20], 1);
  }
  return out;
}

xbuf_t *gw_gen_cookie_header(char *input, xbuf_t **cookie_dst)
{
  xbuf_t *out = (xbuf_t *) malloc(sizeof(xbuf_t))
       , *cookie = gw_gen_cookie(input);
  char buf[32]
     , *time_str = time2rfc(time(NULL) + (60 * 60 * 24 * 365) // 1 year
                             , buf);
  xbuf_init(out);
  xbuf_xcat(out, "Set-Cookie: auth=%s; expires=%s; path=/\r\n"
    , cookie->ptr, time_str);

  // if you need, you can use cookie
  if(cookie_dst) *cookie_dst = cookie;
  else xbuf_free(cookie);
  return out;
}

int add_user (int argc, char *argv[], data_t *data, xbuf_t *reply)
{
  char *username = "";
  char *pass = "";
  char *pass_verify = "";
LINE_
  get_arg("username=", &username, argc, argv);
LINE_
  get_arg("password=", &pass, argc, argv);
LINE_
  get_arg("password_verify=", &pass_verify, argc, argv);

  if(strlen(username) < 1) goto please_fill_form;
LINE_
  if(strstr(username, " ")) goto uname_cant_contain_space;  
LINE_
  if(strlen(pass) < 1) goto please_fill_form;
LINE_
  if(strlen(pass_verify) < 1) goto please_fill_form;

  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "EXISTS username:%s:uid", username);
  if(rr == NULL) return 503;
LINE_
 
  xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
  if(rr->integer == 1)
  {
LINE_
    xbuf_repl(reply, "<!--title-->", "Register / Login- retwis-c");
    xbuf_repl(reply, "<!--content-->", REGISTER_FORM);
    xbuf_repl(reply, "<!--form_errors-->", "[username] is already registered.</br>");
    xbuf_repl(reply, "[username]", username);
LINE_
    return 200;
  }
  else
  {
LINE_
    xbuf_t *pass_sha = to_sha2(pass);
    u64 uid = nextUserId(argv, data);

LINE_
if(pass_sha == NULL) printf("pass_sha is null\n");
    redisReply *rr2 = redisCommand(rc,
     "HMSET uid:%llu username %s pass %s"
    , uid, username, pass_sha->ptr);
if (rr2 == NULL) LINE_

    freeReplyObject(rr2);
LINE_
    rr2 = redisCommand(rc, "SET username:%s:uid %llu"
                         , username, uid);
    freeReplyObject(rr2);
LINE_

    rr2 = redisCommand(rc, "SADD uid:%llu:following %llu"
                         , uid, uid);
LINE_
    freeReplyObject(rr2);

    xbuf_free(pass_sha);
    xbuf_repl(reply, "<!--title-->", "Register / Login- retwis-c");
    xbuf_repl(reply, "<!--content-->",
     "Your account succesfully created. Click <a href=\"/?profile\">here</a> to visit your profile page.");

    // Send cookie to user
    xbuf_t *cookie_buf;
LINE_
    xbuf_t *cookie_header = gw_gen_cookie_header(username, &cookie_buf);
    http_header(HEAD_ADD, cookie_header->ptr, cookie_header->len, argv);
LINE_
    rr2 = redisCommand(rc, "SET auth:%s %llu", cookie_buf->ptr, uid);
LINE_
    freeReplyObject(rr2);

    rr2 = redisCommand(rc, "HSET uid:%llu auth %s", uid,  cookie_buf->ptr);
LINE_
    freeReplyObject(rr2);

LINE_
    xbuf_free(cookie_header);

    return 200;
  }
LINE_
  freeReplyObject(rr);
  return 500; // internal server error

please_fill_form:
LINE_
  xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
  xbuf_repl(reply, "<!--title-->", "Register / Login- retwis-c");
  xbuf_repl(reply, "<!--content-->", "Please fill form.</br>[form]");
LINE_
  return 200;

uname_cant_contain_space:
  xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
  xbuf_repl(reply, "<!--title-->", "Register / Login- retwis-c");
  xbuf_repl(reply, "<!--content-->", "Username can not contain spaces.</br>[form]");
  xbuf_repl(reply, "[form]", REGISTER_FORM);
LINE_
  return 200;
}

int login (int argc, char *argv[], data_t *data)
{
  xbuf_t *reply = get_reply(argv);
  xbuf_t *pass_sha;
  char *username = "";
  char *pass = "";
  char *uid;
  redisContext *rc = data->rc[cur_worker()];

  get_arg("username=", &username, argc, argv);
  get_arg("password=", &pass, argc, argv);

  if(strlen(username) < 1) goto please_fill_form;
  if(strlen(pass) < 1) goto please_fill_form;

  redisReply *rr = redisCommand(rc, "GET username:%s:uid", username);
  if(rr == NULL) return 503;
 
  xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);

  if(rr->type != REDIS_REPLY_NIL)
  {
    uid = strndup(rr->str, rr->len);
    freeReplyObject(rr);
    if(uid == NULL) return 503;

    rr = redisCommand(rc, "HGET uid:%s pass", uid);
    pass_sha = to_sha2 (pass);

    if(pass_sha == NULL)
    {
      freeReplyObject(rr);
      free(uid);
      xbuf_empty(reply);
      return 503;
    }

    if(strcmp(pass_sha->ptr, rr->str) == 0)
    {
      freeReplyObject(rr);
      xbuf_free(pass_sha);
      xbuf_empty(reply);
      free(pass_sha);
      { // Generate cookie header
        xbuf_t *header = (xbuf_t *) malloc(sizeof(xbuf_t));
        char buf[32]
          , *time_str = time2rfc(time(NULL) + (60 * 60 * 24 * 365), buf); // 1 year

        if(header == NULL || time_str == NULL) return 503;

        rr = redisCommand(rc, "HGET uid:%s auth", uid);
        if(rr == NULL)
        {
          free(time_str);
          free(header);
          return 503;
        }

        xbuf_init(header);
        xbuf_xcat(header, "Set-Cookie: auth=%s; expires=%s; path=/\r\nLocation: /?profile\r\n\r\n", rr->str, time_str);

        freeReplyObject(rr);

        http_header(HEAD_ADD, header->ptr, header->len, argv);

        xbuf_free(header);
      }
  //      static char redir[] = "Location: /?profile\r\n\r\n";
  //      http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
      free(uid);
      return 302; // return an HTTP code (302:'Found')
    }

    freeReplyObject(rr);
    xbuf_free(pass_sha);
    free(pass_sha);
    free(uid);

    return 200;
  }
  else
  {
    xbuf_repl(reply, "<!--title-->", "Login - retwis-c");
    xbuf_repl(reply, "<!--register_form-->", LOGIN_FORM);
    xbuf_repl(reply, "<!--form_errors-->", "<p class='text-error'><i class='iconic-hash'></i>username or password is wrong.<p></br>");
    freeReplyObject(rr);
    return 200;
  }

  return 500; // internal server error

please_fill_form:
  xbuf_ncat(reply, data->register_page->ptr, data->register_page->len);
  xbuf_repl(reply, "<!--title-->", "Register / Login- retwis-c");
  xbuf_repl(reply, "<!--content-->", "Please fill form.</br>[form]");
  xbuf_repl(reply, "<!--register_form-->", REGISTER_FORM);
  xbuf_repl(reply, "<!--login_form-->", LOGIN_FORM);
  return 200;
}

xbuf_t *get_timeline (char *argv[], data_t *data, char *uid, int from, int to)
{
  xbuf_t *out = NULL;
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;
  char *username = NULL;

  if(uid == NULL)
    rr = redisCommand(rc, "LRANGE global:timeline %d %d", from, to);
  else
  {
    username = get_username(RA_, uid);
    if(username == NULL) return NULL;
    rr = redisCommand(rc, "LRANGE uid:%s:timeline %d %d", uid, from, to);
  }
  if(rr == NULL || rr->type == REDIS_REPLY_NIL || rr->elements == 0) return NULL;

  out = malloc(sizeof(xbuf_t));
  xbuf_init(out);
  char buf[32];
  for(int i = 0; i < rr->elements; i++)
  {
    redisReply *rr2 = redisCommand(rc, "HMGET post:%s user data time"
      , rr->element[i]->str);
    if(rr2->element[0]->str == NULL) continue;
    char *time_str = time2rfc(atoi(rr2->element[2]->str), buf);

    // this post is viewing user's
    if(uid != NULL && strcmp(username, rr2->element[0]->str) == 0)
    {
      xbuf_xcat(out, 
      "<p>"
        "<strong><a href='/?profile'>%s</a></strong>"
        " <span class='label label-info'><i class='icon-time'></i> %s"
        "</span>"
        "<br/> %s"
      "</p>", rr2->element[0]->str // username
      , time_str, rr2->element[1]->str);
    }
    else
    {
      xbuf_xcat(out, 
      "<p>"
        "<strong><a href='/?profile&user=%s'>%s</a></strong>"
        " <span class='label label-info'><i class='icon-time'></i> %s"
        "</span>"
        "<br/> %s"
      "</p>", rr2->element[0]->str, rr2->element[0]->str // username
      , time_str, rr2->element[1]->str);
    }

    if(time_str) free(time_str);
    freeReplyObject(rr2);
  }

  freeReplyObject(rr);
  if(username != NULL) free(username);
  return out;
}

xbuf_t *get_posts (char *argv[], data_t *data, char *uid, int from, int to)
{
  xbuf_t *out = NULL;
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "LRANGE uid:%s:posts %d %d", uid, from, to);

  if(rr == NULL || rr->type == REDIS_REPLY_NIL || rr->elements == 0) return NULL;

  out = malloc(sizeof(xbuf_t));
  xbuf_init(out);
  char buf[32];
  for(int i = 0; i < rr->elements; i++)
  {
    redisReply *rr2 = redisCommand(rc, "HMGET post:%s user data time"
      , rr->element[i]->str);
    if(rr2->element[0]->str == NULL) continue;
    char *time_str = time2rfc(atoi(rr2->element[2]->str), buf);

    unescape_html((u8*)rr2->element[0]->str);
    xbuf_xcat(out, 
    "<p>"
      "<strong><a href='/?profile&user=%s'>%s</a></strong>"
      "  <span class='label label-info'><i class='icon-time'></i> %s"
        "<a href='/?del_post&postid=%s&return_url=?profile'><i class='icon-trash'></i>"
        " delete</a>"
      "</span>"
      "<br/> %s"
    "</p>", rr2->element[0]->str, rr2->element[0]->str // username
    , time_str, rr->element[i]->str
    , rr2->element[1]->str);

    if(time_str) free(time_str);
    freeReplyObject(rr2);
  }

  freeReplyObject(rr);
  return out;
}

xbuf_t *get_posts_by_username (char *argv[], data_t *data, char *username, int from, int to)
{
  xbuf_t *out = NULL;
  char *uid;
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "GET username:%s:uid", username);

  if(rr == NULL || rr->type == REDIS_REPLY_NIL) return NULL;
  uid = strndup(rr->str, rr->len);
  freeReplyObject(rr);

  out = get_posts(argv, data, uid, from, to);
  return out;
}

int add_post (char *argv[], data_t *data, char *from, char *body, u64 *id_dst)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;
  u64 id = nextPostId(argv, data);
  char *username;

  if(id_dst) *id_dst = id;
  unescape_html((u8 *)body);

  // get username
  rr = redisCommand(rc, "HGET uid:%s username", from);
  if(rr == NULL) return -1;
  username = strndup(rr->str, rr->len);
  freeReplyObject(rr);
  
  // add post to redis
  rr = redisCommand(rc, "HMSET post:%llu user %s uid %s data %s time %d"
     , id, username, from, body, time(0));
  freeReplyObject(rr);
  
  // add post to user's profile
  rr = redisCommand(rc, "LPUSH uid:%s:posts %llu", from, id);
  if(rr == NULL) return -1;
  freeReplyObject(rr);

  // add post to user's timeline
  rr = redisCommand(rc, "LPUSH uid:%s:timeline %llu", from, id);
  if(rr == NULL) return -1;
  freeReplyObject(rr);

  // add post to global timeline
  rr = redisCommand(rc, "LPUSH global:timeline %llu", id);
  if(rr == NULL) return -1;
  freeReplyObject(rr);

  // trim global timeline
  // bunu bir fonksiyon yapacak
  // 10b nin üzerindeki entariler silinecek
  rr = redisCommand(rc, "LTRIM global:timeline 0 10000");
  if(rr == NULL) return -1;
  freeReplyObject(rr);

  // add post to user's followers' timelines
  rr = redisCommand(rc, "SMEMBERS uid:%s:followers", from);
  for(int i = 0; i < rr->elements; i++)
  {
    redisReply *rr2 = redisCommand(rc,
      "LPUSH uid:%s:timeline %llu", rr->element[i]->str, id);
    freeReplyObject(rr2);
  }
  freeReplyObject(rr);
  return 0;
}

void del_post(char *argv[], data_t *data, char *uid, u64 id)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "HGET post:%llu uid", id);
  {
    if(rr->str == NULL) return;
    redisReply *rr2 = redisCommand(rc,
      "SMEMBERS uid:%s:followers", rr->str);
    for(int i = 0; i < rr2->elements; i++)
    {
      if(rr2->element[0]->str == NULL) continue;
      redisReply *rr3 = redisCommand(rc,
       "LREM uid:%s:timeline 1 %llu", rr2->element[i]->str, id);
      freeReplyObject(rr3);
    }
    freeReplyObject(rr2);
  }
  freeReplyObject(rr);

  // delete from user's timeline
  rr = redisCommand(rc,
       "LREM uid:%s:timeline 1 %llu", uid, id);
  freeReplyObject(rr);

  // delete from user's profile
  rr = redisCommand(rc,
       "LREM uid:%s:posts 1 %llu", uid, id);
  freeReplyObject(rr);

  // delete from global timeline
  rr = redisCommand(rc,
       "LREM global:timeline 1 %llu", id);
  freeReplyObject(rr);

  // delete from post
  rr = redisCommand(rc,
       "DEL post:%llu", id);
  freeReplyObject(rr);
}

int follow (char *argv[], data_t *data, char *from, char *to)
{
  u64 rep;
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "SADD uid:%s:following %s", from, to);
  if (rr == NULL) return -1;
  freeReplyObject(rr);

  rr = redisCommand(rc, "SADD uid:%s:followers %s", to, from);
  if (rr == NULL) return -1;

  rep = rr->integer;
  freeReplyObject(rr);

  update_timeline (RA_, from);

  switch(rep)
  {
    case 1: return 0; // Success
    case 0: return 1; // Already following
  }
  return -1;
}

int unfollow (char *argv[], data_t *data, char *from, char *to)
{
  u64 rep;
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;

  rr = redisCommand(rc, "SREM uid:%s:following %s", from, to);
  if (rr == NULL) return -1;
  freeReplyObject(rr);

  rr = redisCommand(rc, "SREM uid:%s:followers %s", to, from);
  if (rr == NULL) return -1;

  rep = rr->integer;
  freeReplyObject(rr);

  update_timeline (RA_, from);

  switch(rep)
  {
    case 1: return 0; // Success
    case 0: return 1; // Already following
  }
  return -1;
}

bool is_following (char *argv[], data_t *data, char *who, char *to_who)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "SISMEMBER uid:%s:following %s", who, to_who);
  if (rr == NULL) return -1;
  if(rr->integer == 1)
  {
    freeReplyObject(rr);
    return true;
  }
  freeReplyObject(rr);
  return false;
}

char *get_username(RETARGS_, char *uid)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;
  char *username;

  // get username
  rr = redisCommand(rc, "HGET uid:%s username", uid);
  if(rr == NULL) return NULL;
  if(rr->str != NULL) username = strndup(rr->str, rr->len);
  else username = NULL;
  freeReplyObject(rr);

  return username;
}

bool user_is_exists (RETARGS_, char *username)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr = redisCommand(rc, "EXISTS username:%s:uid", username);

  if (rr == NULL) return -1;
  if(rr->integer == 1)
  {
    freeReplyObject(rr);
    return true;
  }
  freeReplyObject(rr);
  return false;
}

bool get_from_to_args(int argc, char *argv[], int *from_dst, int *to_dst)
{
  int from, to;
  char *from_str = "";
  char *to_str = "";

  get_arg("from=", &from_str, argc, argv);
  if(strlen(from_str) != 0) from = atoi(from_str);
  else from = 0;
  if(from == -1 || from > 10000)
  {
    return false; // Bad request
  }

  get_arg("to=", &to_str, argc, argv);
  if(strlen(to_str)) to = atoi(to_str);
  else to = 30;
  if(to == -1)
  {
    return false; // Bad request
  }

  if(to < from) to = from + 30;
  if(to > from + 30) to = from + 30;

  if(from_dst != NULL) *from_dst = from;
  if(to_dst   != NULL) *to_dst = to;

  return true;
}

void next_prev_links(xbuf_t *reply, char *url_prefix, int from, int to)
{
  int from2, to2;

  from2 = from > 30 ? from - 30: 0;
  to2 = from > 30 ? to - 30: 30;

  // "prev" link
  xbuf_t *xbuf = malloc(sizeof(xbuf_t));
  xbuf_init(xbuf);
  xbuf_xcat(xbuf, "<p class='act-info next_prev_link' style='font-size: 20px;'><i class='iconic-arrow-left'></i>  <a class='act-primary' href='/%sfrom=%d&to=%d'>prev</a>                                     </p>", url_prefix, from2, to2);
  xbuf_repl(reply, "<!--prev_link-->", xbuf->ptr);
  xbuf_free(xbuf);

  from2 = from > 30 ? (from + 30) : 30;
  to2 = from > 30 ? (to + 30) : 60;

  // "next" link
  xbuf = malloc(sizeof(xbuf_t));
  xbuf_init(xbuf);
  xbuf_xcat(xbuf, "<p class='act-info next_prev_link' style='font-size: 20px;'> <a class='act-primary' href='/%sfrom=%d&to=%d'>next</a> <i class='iconic-arrow-right'></i></p><br/>", url_prefix, from2, to2);
  xbuf_repl(reply, "<!--next_link-->", xbuf->ptr);
  xbuf_free(xbuf);
  free(xbuf);
}

int get_followers_list(RETARGS_, xbuf_t *reply, char *uid_src)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;
  char *username;
  char *uid = uid_src;
  xbuf_t *followers;

  username = get_username(RA_, uid);

  xbuf_repl(reply, "<!--viewing_user's_username-->", username);  

  followers = malloc(sizeof(xbuf_t));
  xbuf_init(followers);

  // add post to user's followers' timelines
  rr = redisCommand(rc, "SMEMBERS uid:%s:followers", uid);

  for(int i = 0; i < (rr->elements > 0 ? rr->elements - 1 : 0); i++)
  {
  // if we use "i < rr->elements - 1;" condition instead of 
  //   "i < rr->elements > 0 ? rr->elements - 1 : 0;" condition,
  //   we get an error "Signal        : 11:Address not mapped to object"
    char *follower = get_username(RA_, rr->element[i]->str);
    xbuf_xcat(followers,
     "<p style='font-size: 15px;'><a class='act-info' href='/?profile&user=%s'><i class='iconic-user'></i> %s</a></p>"
     , follower, follower);
    free(follower);
  }
  
  // delete viewing user from follower list
  {
    xbuf_t *tmp = malloc(sizeof(xbuf_t));
    xbuf_init(tmp);

    xbuf_xcat(tmp,
      "<p style='font-size: 15px;'><a class='act-info' href='/?profile&user=%s'><i class='iconic-user'></i> %s</a></p>"
      , username, username);

    xbuf_repl(followers, tmp->ptr, ""); // delete from followers'list
    
    xbuf_free(tmp);
    free(tmp);
  }

  xbuf_repl(reply, "<!--follower_list-->"
    , followers->len > 0 ? followers->ptr : "<!--viewing_user's_username--> has no followers yet.");

  while(xbuf_repl(reply, "<!--viewing_user's_username-->", username));

  freeReplyObject(rr);
  xbuf_free(followers);
  free(followers);
  free(username);
  free(uid);

  return 200;
}

int get_followings_list(RETARGS_, xbuf_t *reply, char *uid_src)
{
  redisContext *rc = data->rc[cur_worker()];
  redisReply *rr;
  char *username;
  char *uid = uid_src;
  xbuf_t *followings;

  username = get_username(RA_, uid);

  followings = malloc(sizeof(xbuf_t));
  xbuf_init(followings);

  // add post to user's followers' timelines
  rr = redisCommand(rc, "SMEMBERS uid:%s:following", uid);

  for(int i = 0; i < (rr->elements > 0 ? rr->elements - 1 : 0); i++)
  {
  // if we use "i < rr->elements - 1;" condition instead of 
  //   "i < rr->elements > 0 ? rr->elements - 1 : 0;" condition,
  //   we get an error "Signal        : 11:Address not mapped to object"
    char *following = get_username(RA_, rr->element[i]->str);
    xbuf_xcat(followings,
     "<p style='font-size: 15px;'><a class='act-info' href='/?profile&user=%s'><i class='iconic-user'></i> %s</a></p>"
     , following, following);
    free(following);
  }
  
  // delete viewing user from following list
  {
    xbuf_t *tmp = malloc(sizeof(xbuf_t));
    xbuf_init(tmp);

    xbuf_xcat(tmp,
      "<p style='font-size: 15px;'><a class='act-info' href='/?profile&user=%s'><i class='iconic-user'></i> %s</a></p>"
      , username, username);

    xbuf_repl(followings, tmp->ptr, ""); // delete from followings'list

    xbuf_free(tmp);
    free(tmp);
  }

  xbuf_repl(reply, "<!--follower_list-->"
    , followings->len > 0 ? followings->ptr : "<!--viewing_user's_username--> is not following to anyone yet.");

  while(xbuf_repl(reply, "<!--viewing_user's_username-->", username));

  freeReplyObject(rr);
  xbuf_free(followings);
  free(followings);
  free(username);
  free(uid);

  return 200;
}
