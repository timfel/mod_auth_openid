/*
Copyright (C) 2007 Butterfat, LLC (http://butterfat.net)

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

extern "C" module AP_MODULE_DECLARE_DATA authopenid_module;

typedef struct {
  const char *db_location;
  char *trust_root;
  const char *cookie_name;
  char *login_page;
  bool enabled;
  bool use_cookie;
  apr_array_header_t *trusted;
  apr_array_header_t *distrusted;
  int cookie_lifespan;
  char *server_name;
} modauthopenid_config;

typedef const char *(*CMD_HAND_TYPE) ();

static std::string url_encode(const std::string& str) {
  char * t = curl_escape(str.c_str(),str.length());
  if(!t)
    return std::string("");
  std::string rv(t);
  curl_free(t);
  return rv;
}

// get the base directory of the url
static void base_dir(std::string path, std::string& s) {
  // guaranteed that path will at least be "/" - but just to be safe...
  if(path.size() == 0)
    return;
  std::string::size_type q = path.find('?', 0);
  int i;
  if(q != std::string::npos)
    i = path.find_last_of('/', q);
  else
    i = path.find_last_of('/');
  s = path.substr(0, i+1);
}

// make a random alpha-numeric string size characters long
static void make_rstring(int size, std::string& s) {
  s = "";
  const char *cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  srand((unsigned) time(0));
  for(int index=0; index<size; index++)
    s += cs[rand()%62];
}

static void *create_modauthopenid_config(apr_pool_t *p, char *s) {
  modauthopenid_config *newcfg;
  newcfg = (modauthopenid_config *) apr_pcalloc(p, sizeof(modauthopenid_config));
  newcfg->db_location = "/tmp/mod_auth_openid.db";
  newcfg->enabled = false;
  newcfg->use_cookie = true;
  newcfg->cookie_name = "open_id_session_id";
  newcfg->trusted = apr_array_make(p, 5, sizeof(char *));
  newcfg->distrusted = apr_array_make(p, 5, sizeof(char *));
  newcfg->trust_root = NULL;
  newcfg->cookie_lifespan = 0;
  newcfg->server_name = NULL;
  return (void *) newcfg;
}

static const char *set_modauthopenid_db_location(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->db_location = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_trust_root(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->trust_root = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_login_page(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->login_page = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_cookie_name(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->cookie_name = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_enabled(cmd_parms *parms, void *mconfig, int flag) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->enabled = (bool) flag;
  return NULL;
}

static const char *set_modauthopenid_usecookie(cmd_parms *parms, void *mconfig, int flag) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->use_cookie = (bool) flag;
  return NULL;
}

static const char *set_modauthopenid_cookie_lifespan(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->cookie_lifespan = atoi(arg);
  return NULL;
}

static const char *add_modauthopenid_trusted(cmd_parms *cmd, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  *(const char **)apr_array_push(s_cfg->trusted) = arg;
  return NULL;
}

static const char *add_modauthopenid_distrusted(cmd_parms *cmd, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  *(const char **)apr_array_push(s_cfg->distrusted) = arg;
  return NULL;
}

static const char *set_modauthopenid_server_name(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->server_name = (char *) arg;
  return NULL;
} 
 
static const command_rec mod_authopenid_cmds[] = {
  AP_INIT_TAKE1("AuthOpenIDCookieLifespan", (CMD_HAND_TYPE) set_modauthopenid_cookie_lifespan, NULL, OR_AUTHCFG,
		"AuthOpenIDCookieLifespan <number seconds>"),
  AP_INIT_TAKE1("AuthOpenIDDBLocation", (CMD_HAND_TYPE) set_modauthopenid_db_location, NULL, OR_AUTHCFG,
		"AuthOpenIDDBLocation <string>"),
  AP_INIT_TAKE1("AuthOpenIDLoginPage", (CMD_HAND_TYPE) set_modauthopenid_login_page, NULL, OR_AUTHCFG,
		"AuthOpenIDLoginPage <url string>"),
  AP_INIT_TAKE1("AuthOpenIDTrustRoot", (CMD_HAND_TYPE) set_modauthopenid_trust_root, NULL, OR_AUTHCFG,
		"AuthOpenIDTrustRoot <trust root to use>"),
  AP_INIT_TAKE1("AuthOpenIDCookieName", (CMD_HAND_TYPE) set_modauthopenid_cookie_name, NULL, OR_AUTHCFG,
		"AuthOpenIDCookieName <name of cookie to use>"),
  AP_INIT_FLAG("AuthOpenIDEnabled", (CMD_HAND_TYPE) set_modauthopenid_enabled, NULL, OR_AUTHCFG,
	       "AuthOpenIDEnabled <On | Off>"),
  AP_INIT_FLAG("AuthOpenIDUseCookie", (CMD_HAND_TYPE) set_modauthopenid_usecookie, NULL, OR_AUTHCFG,
	       "AuthOpenIDUseCookie <On | Off> - use session auth?"),
  AP_INIT_ITERATE("AuthOpenIDTrusted", (CMD_HAND_TYPE) add_modauthopenid_trusted, NULL, OR_AUTHCFG,
		  "AuthOpenIDTrusted <a list of trusted identity providers>"),
  AP_INIT_ITERATE("AuthOpenIDDistrusted", (CMD_HAND_TYPE) add_modauthopenid_distrusted, NULL, OR_AUTHCFG,
		  "AuthOpenIDDistrusted <a blacklist list of identity providers>"),
  AP_INIT_TAKE1("AuthOpenIDServerName", (CMD_HAND_TYPE) set_modauthopenid_server_name, NULL, OR_AUTHCFG,
		"AuthOpenIDServerName <server name and port prefix>"),
  {NULL}
};

/* Get the full URI of the request_rec's request location */
static void full_uri(request_rec *r, std::string& result, modauthopenid_config *s_cfg) {
  std::string hostname(r->hostname);
  std::string protocol(r->protocol);
  std::string uri(r->uri);
  apr_port_t i_port = ap_get_server_port(r);
  std::string prefix = (i_port == 443) ? "https://" : "http://";
  char *port = apr_psprintf(r->pool, "%lu", (unsigned long) i_port);
  std::string s_port = (i_port == 80 || i_port == 443) ? "" : ":" + std::string(port);
  std::string args = (r->args == NULL) ? "" : "?" + std::string(r->args);
  if(s_cfg->server_name == NULL)
    result = prefix + hostname + s_port + uri + args;
  else
    result = std::string(s_cfg->server_name) + uri + args;
}

static int show_input(request_rec *r, modauthopenid_config *s_cfg, modauthopenid::error_result_t e) {
  if(s_cfg->login_page == NULL) {
    std::string msg = modauthopenid::error_to_string(e, false);
    return modauthopenid::show_html_input(r, msg);
  }
  opkele::params_t params;
  if(r->args != NULL) 
    params = modauthopenid::parse_query_string(std::string(r->args));
  params = modauthopenid::remove_openid_vars(params);  
  params["modauthopenid.error"] = modauthopenid::error_to_string(e, true);
  return modauthopenid::http_redirect(r, params.append_query(s_cfg->login_page, ""));
}

static int show_input(request_rec *r, modauthopenid_config *s_cfg) {
  if(s_cfg->login_page == NULL) 
    return modauthopenid::show_html_input(r, "");
  opkele::params_t params;
  if(r->args != NULL) 
    params = modauthopenid::parse_query_string(std::string(r->args));
  params = modauthopenid::remove_openid_vars(params);
  std::string uri_location;
  full_uri(r, uri_location, s_cfg);
  params["modauthopenid.referrer"] = uri_location;
  return modauthopenid::http_redirect(r, params.append_query(s_cfg->login_page, ""));
}

static bool is_trusted_provider(modauthopenid_config *s_cfg, std::string url) {
  if(apr_is_empty_array(s_cfg->trusted))
    return true;
  char **trusted_sites = (char **) s_cfg->trusted->elts;
  std::string base_url = modauthopenid::get_queryless_url(url);
  for (int i = 0; i < s_cfg->trusted->nelts; i++) {
    if(modauthopenid::regex_match(base_url, trusted_sites[i])) {
      modauthopenid::debug(base_url + " is a trusted identity provider");
      return true;
    }
  }
  modauthopenid::debug(base_url + " is NOT a trusted identity provider");
  return false;
}

static bool is_distrusted_provider(modauthopenid_config *s_cfg, std::string url) {
  if(apr_is_empty_array(s_cfg->distrusted))
    return false;
  char **distrusted_sites = (char **) s_cfg->distrusted->elts;
  std::string base_url = modauthopenid::get_queryless_url(url);
  for (int i = 0; i < s_cfg->distrusted->nelts; i++) {
    if(modauthopenid::regex_match(base_url, distrusted_sites[i])) {
      modauthopenid::debug(base_url + " is a distrusted (on black list) identity provider");
      return true;
    }
  }
  modauthopenid::debug(base_url + " is NOT a distrusted identity provider (not blacklisted)");
  return false;
}

static int mod_authopenid_method_handler(request_rec *r) {
  modauthopenid_config *s_cfg;
  s_cfg = (modauthopenid_config *) ap_get_module_config(r->per_dir_config, &authopenid_module);

  // if we're not enabled for this location/dir, decline doing anything
  if(!s_cfg->enabled) 
    return DECLINED;
  
  // make a record of our being called
  modauthopenid::debug("***" + std::string(PACKAGE_STRING) + " module has been called***");

  // test for valid session - if so, return DECLINED
  std::string session_id = "";
  modauthopenid::get_session_id(r, std::string(s_cfg->cookie_name), session_id);
  if(session_id != "" && s_cfg->use_cookie) {
    modauthopenid::debug("found session_id in cookie: " + session_id);
    modauthopenid::SESSION session;
    modauthopenid::SessionManager sm(std::string(s_cfg->db_location));
    sm.get_session(session_id, session);
    sm.close();

    // if session found 
    if(std::string(session.identity) != "") {
      std::string uri_path;
      base_dir(std::string(r->uri), uri_path);
      std::string valid_path(session.path);
      // if found session has a valid path
      if(valid_path == uri_path.substr(0, valid_path.size()) && apr_strnatcmp(session.hostname, r->hostname)==0) {
	modauthopenid::debug("setting REMOTE_USER to \"" + std::string(session.identity) + "\"");
	r->user =  apr_pstrdup(r->pool, std::string(session.identity).c_str());
	return DECLINED;
      } else {
	modauthopenid::debug("session found for different path or hostname");
      }
    }
  }

  // parse the get params
  opkele::params_t params;
  if(r->args != NULL) params = modauthopenid::parse_query_string(std::string(r->args));
  std::string identity = (params.has_param("openid.identity")) ? opkele::consumer_t::normalize(params.get_param("openid.identity")) : "unknown";

  // if user is posting id (only openid.identity will contain a value)
  if(params.has_param("openid.identity") && !params.has_param("openid.assoc_handle")) {
    // remove all openid GET query params (openid.*) - we don't want that maintained through
    // the redirection process.  We do, however, want to keep all aother GET params.
    // also, add a nonce for security
    params = modauthopenid::remove_openid_vars(params);
    modauthopenid::NonceManager nm(std::string(s_cfg->db_location));
    std::string nonce;
    make_rstring(10, nonce);
    nm.add(nonce, identity);
    nm.close();
    params["openid.nonce"] = nonce;
    //remove first char - ? to fit r->args standard
    std::string args = params.append_query("", "").substr(1); 
    apr_cpystrn(r->args, args.c_str(), 1024);
    if(!modauthopenid::is_valid_url(identity))
      return show_input(r, s_cfg, modauthopenid::invalid_id_url);
    modauthopenid::MoidConsumer consumer(std::string(s_cfg->db_location));     
    std::string return_to, trust_root, re_direct;
    full_uri(r, return_to, s_cfg);
    if(s_cfg->trust_root == NULL)
      base_dir(return_to, trust_root);
    else
      trust_root = std::string(s_cfg->trust_root);
    try {
      re_direct = consumer.checkid_setup(identity, return_to, trust_root);
    } catch (opkele::exception &e) {
      consumer.close();
      modauthopenid::debug("Error while fetching idP location: " + std::string(e.what()));
      return show_input(r, s_cfg, modauthopenid::no_idp_found);
    }
    consumer.close();
    if(!is_trusted_provider(s_cfg , re_direct) || is_distrusted_provider(s_cfg, re_direct))
       return show_input(r, s_cfg, modauthopenid::idp_not_trusted);
    return modauthopenid::http_redirect(r, re_direct);
  } else if(params.has_param("openid.assoc_handle")) { // user has been redirected, authenticate them and set cookie
    // make sure nonce is present
    if(!params.has_param("openid.nonce"))
      return show_input(r, s_cfg, modauthopenid::invalid_nonce);
    modauthopenid::MoidConsumer consumer(std::string(s_cfg->db_location));
    try {
      consumer.id_res(params);
      consumer.close();

      // if no exception raised, check nonce
      modauthopenid::NonceManager nm(std::string(s_cfg->db_location));
      if(!nm.is_valid(params.get_param("openid.nonce"))) {
	nm.close();
	return show_input(r, s_cfg, modauthopenid::invalid_nonce); 
      }
      // Make sure that identity is set to the original one given by the user (in case of delegation
      // this will be different than openid.identity GET param
      nm.get_identity(params.get_param("openid.nonce"), identity);
      nm.delete_nonce(params.get_param("openid.nonce"));
      nm.close();

      if(s_cfg->use_cookie) {
	// now set auth cookie, if we're doing session based auth
	std::string session_id, hostname, path, cookie_value, redirect_location, args;
	make_rstring(32, session_id);
	base_dir(std::string(r->uri), path);
	modauthopenid::make_cookie_value(cookie_value, std::string(s_cfg->cookie_name), session_id, path, s_cfg->cookie_lifespan); 
	modauthopenid::debug("setting cookie: " + cookie_value);
	apr_table_setn(r->err_headers_out, "Set-Cookie", cookie_value.c_str());
	hostname = std::string(r->hostname);

	// save session values
	modauthopenid::SessionManager sm(std::string(s_cfg->db_location));
	sm.store_session(session_id, hostname, path, identity);
	sm.close();

	params = modauthopenid::remove_openid_vars(params);
	args = params.append_query("", "").substr(1);
	if(args.length() == 0)
	  r->args = NULL;
	else
	  apr_cpystrn(r->args, args.c_str(), 1024);
	full_uri(r, redirect_location, s_cfg);
	return modauthopenid::http_redirect(r, redirect_location);
      }
      
      // if we're not setting cookie - don't redirect, just show page
      modauthopenid::debug("setting REMOTE_USER to \"" + identity + "\"");
      r->user = apr_pstrdup(r->pool, identity.c_str());
      return DECLINED;

    } catch(opkele::exception &e) {
      modauthopenid::debug("Error in authentication: " + std::string(e.what()));
      consumer.close();
      return show_input(r, s_cfg, modauthopenid::unspecified);
    }
  } else { //display an input form
    if(params.has_param("openid.mode") && params.get_param("openid.mode") == "cancel")
      return show_input(r, s_cfg, modauthopenid::canceled);
    return show_input(r, s_cfg);
  }
}

static void mod_authopenid_register_hooks (apr_pool_t *p) {
  ap_hook_handler(mod_authopenid_method_handler, NULL, NULL, APR_HOOK_FIRST);
}

//module AP_MODULE_DECLARE_DATA 
module AP_MODULE_DECLARE_DATA authopenid_module = {
	STANDARD20_MODULE_STUFF,
	create_modauthopenid_config,
	NULL, // config merge function - default is to override
	NULL,
	NULL,
	mod_authopenid_cmds,
	mod_authopenid_register_hooks,
};
