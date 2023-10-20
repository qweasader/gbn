# SPDX-FileCopyrightText: 2004 Westpoint Limited and Corsaire Limited
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# DISCLAIMER
# The information contained within this script is supplied "as-is" with
# no warranties or guarantees of fitness of use or otherwise. Corsaire
# accepts no responsibility for any damage caused by the use or misuse of
# this information.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12300");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0050");
  script_name("Inktomi Search Physical Path Disclosure");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Westpoint Limited and Corsaire Limited");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Ultraseek/banner");
  script_require_ports("Services/www", 8765);

  script_xref(name:"URL", value:"http://www.corsaire.com/advisories/c040113-001.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8050");

  script_tag(name:"solution", value:"Upgrade to the latest version. This product is now developed
  by Verity and is called Ultraseek");

  script_tag(name:"summary", value:"This web server is running a vulnerable version of Inktomi Search.");

  script_tag(name:"impact", value:"Certain requests using MS-DOS special file names such as nul can cause
  a python error. The error message contains sensitive information such as the physical path of the webroot.
  This information may be useful to an attacker.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8765);

# some other servers may crash the host when requested
# for a DOS device.
banner = http_get_remote_headers(port:port);
if( ! banner || "Server: Ultraseek" >!< banner ) exit(0);

req = http_get(item:"/nul", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( ! res ) exit(0);
if( "httpsrvr.py:1033" >!< res || "500 Internal Server Error" >!< res ) exit(0);

w = egrep(pattern:"directory", string:res);
if(w) {
  webroot = ereg_replace(string:w, pattern:"^.*'(.*)'.*$", replace:"\1");
  if (webroot == w) exit(0);
  report = "The remote web root is : " + w;
  security_message(port:port, data:report);
}

exit(0);
