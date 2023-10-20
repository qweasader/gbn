# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11066");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4269");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-0436");
  script_name("SunSolve CD CGI user input validation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8383);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Sunsolve CD CGI scripts does not validate user input.");

  script_tag(name:"impact", value:"An attacker may use them to execute some commands on the target system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:8383);

if(http_is_cgi_installed_ka(port:port, item:"/cd-cgi/sscd_suncourier.pl")) {
  security_message(port:port);
  exit(0);
}

if(http_is_cgi_installed_ka(port:port, item:"sscd_suncourier.pl")) {
  security_message(port:port);
  exit(0);
}

exit(99);
