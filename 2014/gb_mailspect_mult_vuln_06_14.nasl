# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105050");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2023-07-26T05:05:09+0000");
  script_name("Mailspect Control Panel Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/137");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-26 11:36:16 +0200 (Thu, 26 Jun 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 20001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker can exploit these issues to obtain sensitive information
or to execute arbitrary script code or to execute arbitrary code in the context of
the application.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response");
  script_tag(name:"insight", value:"Mailspect Control Panel is prone to

1. a remote code execution (Authenticated)

2. two arbitrary file read (Authenticated)

3. a cross site scripting vulnerability (Unauthenticated)");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Mailspect Control Panel is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"Mailspect Control Panel version 4.0.5");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:20001 );

vt_strings = get_vt_strings();

url = '/login.cgi?login=' + vt_strings["default"] + '"><script>alert(/' + vt_strings["lowercase"] + '/)</script>';

if( http_vuln_check( port:port, url:url,pattern:"<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",
                     check_header:TRUE, extra_check:"<title>Login to Mailspect Control Panel" ) ) {
  security_message(port:port);
  exit(0);
}

exit(0);
