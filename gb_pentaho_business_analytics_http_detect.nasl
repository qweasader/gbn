# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808205");
  script_version("2024-08-02T15:38:45+0000");
  script_tag(name:"last_modification", value:"2024-08-02 15:38:45 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2016-05-24 17:56:31 +0530 (Tue, 24 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pentaho Business Analytics Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Pentaho Business Analytics.");

  script_add_preference(name:"Pentaho Business Analytics Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Pentaho Business Analytics Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.hitachivantara.com/en-us/products/data-management-analytics/pentaho.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

foreach dir (make_list_unique("/", "/pentaho", "/pentaho-solutions", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/Login";

  res = http_get_cache(port: port, item: url);

  if ("<title>Pentaho User Console - Login</title>" >< res &&
      "j_username" >< res && "j_password" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    user = script_get_preference("Pentaho Business Analytics Web UI Username", id: 1);
    pass = script_get_preference("Pentaho Business Analytics Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
    } else if (!user && pass) {
      extra += "Note: Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "Note: Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      url = dir + "/j_spring_security_check";

      headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                           "X-Requested-With", "XMLHttpRequest");

      data = "j_username=" + user + "&j_password=" + pass;

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 302" && "login_error" >!< res) {
        cookie = http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID=[^;]+)");
        if (!isnull(cookie)) {
          url = dir + "/api/version/show";

          headers = make_array("Cookie", cookie);

          req = http_get_req(port: port, url: url, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req);

          if (res =~ "^HTTP/1\.[01] 200") {
            body = http_extract_body_from_response(data: res);
            # 10.1.0.0.317
            vers = eregmatch(pattern: "([0-9.]+)", string: body);
            if (!isnull(vers[1])) {
              version = vers[1];
              conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
            }
          }
        }
      } else {
        extra += "Note: Username and password were provided but authentication failed.";
      }
    }

    if (version == "unknown") {
      # nb: This is just the major version and should not be used for version checks
      url = dir + "/docs/InformationMap.jsp";
      res = http_get_cache(port: port, item: url);
      # var docBase = "https://help.pentaho.com/Documentation/8.0/";
      # <div id="title">PDF Documentation for Pentaho 5.0</div>
      vers = eregmatch(pattern: "/Documentation/([0-9.]+)/", string: res);
      if (isnull(vers[1]))
        vers = eregmatch(pattern: "Pentaho ([0-9.]+)<", string: res);

      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name:"pentaho/business_analytics/detected", value: TRUE);
    set_kb_item(name:"pentaho/business_analytics/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hitachivantara:pentaho_business_analytics:");
    if (!cpe)
      cpe = "cpe:/a:hitachivantara:pentaho_business_analytics";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Pentaho Business Analytics", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: conclUrl, extra: extra),
                port:port);
    exit(0);
  }
}

exit(0);
