# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11771");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8024");
  script_cve_id("CVE-2003-0471");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("webadmin.dll detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version if necessary.");

  script_tag(name:"summary", value:"webadmin.dll was found on your web server.
  Old versions of this CGI suffered from numerous problems:

  - installation path disclosure

  - directory traversal, allowing anybody with
   administrative permission on WebAdmin to read any file

  - buffer overflow, allowing anybody to run arbitrary code on
   your server with SYSTEM privileges.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
res = http_is_cgi_installed_ka( port:port, item:"webadmin.dll" );
if( res ) {
  security_message( port:port );
}

exit( 0 );
