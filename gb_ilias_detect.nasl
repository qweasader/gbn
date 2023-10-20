# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140443");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2017-10-20 10:51:43 +0700 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ILIAS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of ILIAS eLearning.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ilias.de");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/ilias", "/ILIAS", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  # login.php often needs some parameters so we check over setup.php
  url = dir + "/setup/setup.php";
  # http_get_cache() doesn't make sense here since we get a unique session id anyway
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if (!res)
    continue;

  # We should get a redirect with a session id
  loc = http_extract_location_from_redirect(port: port, data: res, current_dir: install);
  if (isnull(loc))
    continue;

  cookie = http_get_cookie_from_header( buf: res, pattern: "[Ss]et-[Cc]ookie\s*:\s*(SESSID=[0-9A-Za-z]+);");
  # nb: If there is no such cookie (which might be possible) create a random one to avoid an error in make_array below
  if (!cookie)
    cookie = "SESSID=" + rand_str(length: 32, charset: "abcdefghijklmnopqrstuvwxyz0123456789");
  req = http_get_req( port:port, url:loc, add_headers:make_array( "Cookie", cookie));
  res = http_keepalive_send_recv(port: port, data: req);

  # <title>ILIAS Setup</title>
  # <title>ILIAS 3 Setup</title>
  if ((res =~ "<title>ILIAS ([0-9] )?Setup</title>" || "<title>ILIAS Setup</title>" >< res) &&
      ("std setup ilSetupLogin" >< res || 'class="ilSetupLogin">' >< res ||
       'class="ilLogin">' >< res || 'class="il_Header">' >< res)) {
    version = "unknown";

    # <small>ILIAS 3.10.5 2009-03-06 (Setup Version 2 Revision: 17651)</small>
    # <small>ILIAS 4.4.6 2014-11-22 (Setup Version 2 Revision: 49592)</small>
    # <div class="row">ILIAS 5.1.13 2016-12-22 (Setup Version 2 Revisio)</div>
    vers = eregmatch(pattern: '(class="row">|<small>)ILIAS ([0-9.]+)', string: res);
    if (!isnull(vers[2])) {
      version = vers[2];
    } else {
      # Some versions requires another request to the login.php to get the real version
      # e.g. 3.4 had only <small>ILIAS3 - setup Version 2.1.61.4.5</small> on the setup page
      url = "/login.php?lang=en";
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);
      # <p class="very_small">powered by <b>ILIAS</b> (v3.4.3 2005-06-15)</p>
      vers = eregmatch(pattern: ">powered by <b>ILIAS</b> \(v([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
      }
    }

    set_kb_item(name: "ilias/version", value: version);
    set_kb_item(name: "ilias/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ilias:ilias:");
    if (!cpe)
      cpe = "cpe:/a:ilias:ilias";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "ILIAS", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE )),
                port: port);
    exit(0);
  }
}

exit(0);
