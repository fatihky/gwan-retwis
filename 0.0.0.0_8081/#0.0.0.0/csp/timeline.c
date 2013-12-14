#include "retwis.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
  data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
       , *data = NULL;
  xbuf_t *reply = get_reply ( argv );
  int from, to;
  char *public = NULL;
  char is_public = false; // are we will render this page as a public timeline?

  switch(init_data(argv, Data))
  {
    case 0: data = *Data; break;
    case 1: return 500;
    default: return 503;
  }

  if(get_from_to_args(argc, argv, &from, &to) == false) return 400;

  get_arg("public=", &public, argc, argv);
  if(public != NULL && strlen(public) > 3)
  {
    if(strcmp(public, "true") == 0) is_public = true;
    else if(strcmp(public, "false") == 0) is_public = false;
  }

  char *uid = NULL;
  int auth = is_member(argv, data, &uid);
/*
  if(auth != true)
  {
    static char redir[] = "Location: /?register\r\n\r\n";
    http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
    return 302; // return an HTTP code (302:'Found')
  }
*/
  xbuf_ncat(reply, data->main_page->ptr, data->main_page->len);
  xbuf_repl(reply, "<!--title-->", "Timeline - retwis-c");

  // Generate auth based links to main menu
  auth_based_links(reply, auth, auth);

  if(auth == true)  xbuf_repl(reply, "<!--new_post_form-->", NEW_POST_FORM);

  xbuf_t *timeline;
  if(auth == true && is_public == false)
    timeline = get_timeline(argv, data, uid, from, to);
  else timeline = get_timeline(argv, data, NULL, from, to);
  xbuf_repl(reply, "<!--timeline-->", timeline ? timeline->ptr : "We couldn't find anything.</br>");
  xbuf_free(timeline);

  if(auth == true && is_public == false) next_prev_links(reply, "?profile&", from, to);
  else 
  {
    if(is_public == true)
      next_prev_links(reply, "&public=true&", from, to);
  }

  if(is_public == true)  xbuf_repl(reply, "<!--is_public_link-->", "<br/><p style='font-size: 15px;'><i class='iconic-o-check' style='color: #51A351; display: inline;'></i> you are viewing public timeline | <a class='act-info' href='/?timeline'><i class='iconic-user'></i> view own timeline</a></p><br/>");
  else if(auth == true)  xbuf_repl(reply, "<!--is_public_link-->", "<br/><p style='font-size: 15px;'><i class='iconic-o-check' style='color: #51A351; display: inline;'></i> you are viewing your own timeline | <a class='act-info' href='/?timeline&public=true'><i class='iconic-user'></i> view public timeline</a></p><br/>");

  if(uid != NULL) free(uid);
  return 200;
}
