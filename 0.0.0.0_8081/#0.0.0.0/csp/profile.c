#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
  xbuf_t *reply = get_reply ( argv );
  int from, to;
  char *from_str = "";
  char *to_str = "";
LINE_

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }
LINE_
  
  char *uid = NULL;
  char *username    = "";
  char *from_follow = "";
  int auth = is_member(argv, data, &uid);
  if(auth != true && argc == 0)
  {
LINE_
    if(auth == true) free(uid);
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }

LINE_
  get_arg("from=", &from_str, argc, argv);
LINE_
  if(strlen(from_str) != 0) from = atoi(from_str);
  else from = 0;
LINE_
  if(from == -1 || from > 10000)
  {
LINE_
    free(uid);
    return 400; // Bad request
  }

  get_arg("to=", &to_str, argc, argv);
LINE_
  if(strlen(to_str)) to = atoi(to_str);
  else to = 30;
LINE_
  if(to == -1)
  {
LINE_
    free(uid);
    return 400; // Bad request
  }

LINE_
  if(to < from) to = from + 30;
LINE_
  if(to > from + 30) to = from + 30;

  xbuf_ncat(reply, data->profile_page->ptr, data->profile_page->len);
LINE_
  xbuf_repl(reply, "<!--title-->", "Profile - retwis-c");

  // Generate auth based links to main menu
  auth_based_links(reply, auth, false);
LINE_

  xbuf_t *timeline = NULL;
LINE_
  get_arg("user=", &username, argc, argv);
LINE_
  size_t username_len = strlen(username);
LINE_

  // is this page viewing user's profile?
  bool this_page_is_viewing_users = false;
LINE_
  char *username2 = get_username(RA_, uid);
LINE_
  if(strcmp(username, username2) == 0) this_page_is_viewing_users = true;
LINE_

  if(username_len != 0)
  {
LINE_
    bool is_following_int = 0;
    bool user_exists = user_is_exists(RA_, username);
LINE_

    if(user_exists == 0)
    {
LINE_
      xbuf_empty(reply);
      if(auth == true)
        free(uid);
      return 404;
    }

    if(auth == true)
    {
LINE_
      char *uid2 = get_uid_from_username (RA_, username);
      is_following_int = is_following (RA_, uid, uid2);
      free(uid2);
LINE_
    }

    timeline = get_posts_by_username (RA_, username, from, to);

    // rendering the page

LINE_
    xbuf_repl(reply, "<!--timeline-->", timeline ? timeline->ptr : from > 0 ? "we couldn't find anything.<br/>": "<p class='act-info'><a class='act-primary' href='/?profile&user=[viewing_user]'>[viewing_user]</a> didn't send anything yet.</p></br>");

LINE_
    get_arg("from_follow=", &from_follow, argc, argv);
    if(auth == true && this_page_is_viewing_users == false && strlen(from_follow))
    {
LINE_
      if(strcmp(from_follow, "success") == 0)    
        xbuf_repl(reply, "<!--messages-->", "<p class='text-success'><i class='iconic-hash'></i>You are following [viewing_user] now.<p>");
      else if(strcmp(from_follow, "unfollow") == 0)
        xbuf_repl(reply, "<!--messages-->", "<p class='text-warning'><i class='iconic-hash'></i>You are not following [viewing_user] no longer.<p>");
      else if(strcmp(from_follow, "already_not_following") == 0)
        xbuf_repl(reply, "<!--messages-->", "<p class='text-warning'><i class='iconic-hash'></i>You are already not following [viewing_user].<p>");
      else
        xbuf_repl(reply, "<!--messages-->", "<p class='text-error'><i class='iconic-hash'></i>You are already following [viewing_user].<p>");
LINE_
    }

    // <!--follow_unfollow_link-->
    // <button class="btn btn-large btn-primary" type="button">Large button</button>
    // btn btn-inverse btn btn-success
    // style="color: #51A351"
    // icon-o-check
    // act-success act-danger act-info
    // label label-info

    if(auth == true && this_page_is_viewing_users == false)
    {
LINE_
      if(is_following_int == true)
      {
LINE_
        xbuf_repl(reply, "<!--follow_unfollow_link-->"
         , "<br/><p style='font-size: 20px;'><a href='/?profile&user=[viewing_user]'><i class='iconic-user'></i>[viewing_user]</a> | <i class='iconic-o-check' style='color: #51A351; display: inline;'></i> takip ediliyor | <a class='act-warning' href='/?unfollow&to=[viewing_user]'>takip etmeyi bırak</a></p><br/>");
      }
      else
      {
LINE_
        xbuf_repl(reply, "<!--follow_unfollow_link-->"
         , "<br/><p style='font-size: 20px;'><a href='/?profile&user=[viewing_user]'><i class='iconic-user'></i>[viewing_user]</a> | <a class='act-success' href='/?follow&to=[viewing_user]'>takip et</a></p><br/>");
      }        
    }

    while(xbuf_repl(reply, "[viewing_user]", username));
LINE_

  } else  if(username_len == 0 && auth != true) {
      xbuf_repl(reply, "<!--timeline-->", "we couldn't find anything...");
  } else {
LINE_
    timeline = get_posts(argv, data, uid, from, to);

    if(from == 0) xbuf_repl(reply, "<!--timeline-->", timeline ? timeline->ptr : "You didn't send anything.<br/>");
    else xbuf_repl(reply, "<!--timeline-->", timeline ? timeline->ptr : "we couldn't find anything.<br/>");
  }

  if(auth == true)
  {
LINE_
    if(this_page_is_viewing_users == true || username_len == 0)
      xbuf_repl(reply, "<!--new_post_form-->", NEW_POST_FORM);
    free(uid);
  }

  if(username_len == 0) next_prev_links(reply, "?profile&", from, to);
  else
  {
LINE_
    xbuf_t *urlbuf = malloc(sizeof(xbuf_t));
    xbuf_init(urlbuf);
    xbuf_xcat(urlbuf, "?profile&user=%s&", username);

    next_prev_links(reply, urlbuf->ptr, from, to);

    xbuf_free(urlbuf);
    free(urlbuf);
LINE_
  }

LINE_
  return 200;
}
