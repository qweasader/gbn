# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11070");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0937");
  script_name("PGPMail.pl detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/82/243262");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3605");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/243408");

  script_tag(name:"solution", value:"Remove it from /cgi-bin or upgrade it.");

  script_tag(name:"summary", value:"The 'PGPMail.pl' CGI is installed.

  Some versions (up to v1.31 a least) of this CGI do not
  properly filter user input before using it inside commands.");

  script_tag(name:"impact", value:"This would allow an attacker to run any command on the web server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

res = http_is_cgi_installed_ka(port:port, item:"PGPMail.pl");
if(res) {
  security_message(port:port);
  exit(0);
}

exit(99);
