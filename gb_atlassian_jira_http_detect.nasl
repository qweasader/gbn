# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902046");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian JIRA Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Atlassian JIRA.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.atlassian.com/software/jira");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 8080);

foreach dir (make_list_unique("/", "/jira", http_cgi_dirs(port: port))) {

  found = 0;
  setup_mode_page = FALSE;
  install = dir;
  if (dir == "/")
    dir = "";

  url1 = dir + "/login.jsp";
  res1 = http_get_cache(port: port, item: url1);

  # Atlassian JIRA
  # or:
  # Atlassian Jira
  # so a case insensitive =~ is used here
  if (res1 =~ "Atlassian JIRA")
    found++;

  # nb: Should count together as one to avoid flagging a different product using similar pages
  if ("/secure/Dashboard.jspa" >< res1 || "/secure/AboutPage.jspa" >< res1)
    found++;

  # <title>Log in - Jira</title>
  # <title>Log in - Sometext Jira</title>
  if (res1 =~ "<title>Log in - [^<]*Jira</title>")
    found++;

  if (">About Jira</a>" >< res1)
    found++;

  if (found > 1)
    conclUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

  if (found <= 1) {
    url2 = dir + "/startup.jsp";
    res2 = http_get_cache(port: port, item: url2);

    # <h1>Atlassian Jira is starting up</h1>
    #
    # nb: the "-" below was the UTF-8 char for the dash and has been replaced here to avoid any
    # encoding problems. That's why a "." is used in the second regex...
    # <title>Atlassian Jira - Initializing</title>
    if (res2 =~ "(<h1>Atlassian Jira is starting up</h1>|<title>Atlassian Jira . Initializing</title>)") {
      found = 2;
      conclUrl = http_report_vuln_url(port: port, url: url2, url_only: TRUE);
    }
  }

  if (found <= 1) {
    # nb: Some systems might be in some kind of error state
    url3 = dir + "/secure/SetupMode!default.jspa";
    res3 = http_get_cache(port: port, item: url3);

    # If in some kind of error state:
    # <h1>Sorry, we had some technical problems during your last operation.</h1>
    # <p>Copy the content below and send it to your Jira Administrator</p>
    # <p>Copy the content below and send it to your JIRA Administrator</p>
    #
    # or in "normal" operation:
    # <title>Jira setup has already completed - redacted</title>
    #
    # or if not configured yet:
    # <title>Jira - Jira setup</title>
    # <title>JIRA - JIRA setup</title>
    #
    # nb:
    # - This is also catching systems having a "SSO plugin" ("/plugins/servlet/samlsso") enabled
    # - The matches below are case insensitive (=~) due to the different Jira vs. JIRA above
    if (res3 =~ "<title>Jira setup has already completed" ||
        res3 =~ "<title>Jira - Jira setup</title>" ||
         (">Sorry, we had some technical problems during your last operation.<" >< res3 &&
           res3 =~ ">Copy the content below and send it to your JIRA Administrator<")
       ) {
      found = 2;
      setup_mode_page = TRUE;
      conclUrl = http_report_vuln_url(port: port, url: url3, url_only: TRUE);
    }
  }

  if (found > 1) {
    version = "unknown";
    # <meta name="ajs-version-number" content="9.6.0">
    # <meta name="ajs-version-number" content="8.22.4">
    vers = eregmatch(pattern: '<meta name="ajs-version-number" content="([0-9.]+)">', string:res1);
    if (!isnull(vers[1]))
      version = vers[1];

    if( version == "unknown") {
      # <span id="footer-build-information" class="smallgreyfooter" >(v4.4.3#663-r165197)</span>
      # <span id="footer-build-information">(v7.5.0#75005-<span title='fd8c849d4e278dd8bbaccc61e707a716ad697024'
      # <span id="footer-build-information">(v8.9.0#809000-<span title='4ceb90abd8e813f4565a1705e597aeab0a82fc50'
      vers = eregmatch(pattern: '"footer-build-information"[^v]+v([0-9.]+)', string: res1);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    # nb:
    # - Same as above but from the error / setup page (if available)
    # - Only older Jira versions contains this build information
    if( version == "unknown" && setup_mode_page) {
      vers = eregmatch(pattern: '"footer-build-information"[^v]+v([0-9.]+)', string: res3);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    set_kb_item(name: "atlassian/jira/detected", value: TRUE);
    set_kb_item(name: "atlassian/jira/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:jira:");
    if (!cpe)
      cpe = "cpe:/a:atlassian:jira";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Atlassian JIRA", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);

    exit(0);
  }
}

exit(0);
