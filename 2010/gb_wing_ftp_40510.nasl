# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100665");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-03 13:39:07 +0200 (Thu, 03 Jun 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2428");

  script_name("Wing FTP Server 'admin_loginok.html' HTML Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40510");
  script_xref(name:"URL", value:"http://www.wftpserver.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511612");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5466);
  script_mandatory_keys("Wing_FTP_Server/banner");

  script_tag(name:"summary", value:"Wing FTP Server is prone to an HTML-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of
  the affected site, potentially allowing the attacker to steal cookie-
  based authentication credentials and to control how the site is
  rendered to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"Wing FTP Server 3.5.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:5466);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Wing FTP Server" >!< banner)exit(0);

version = eregmatch(pattern:"Wing FTP Server/([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version: "3.5.0")) {
  security_message(port:port);
  exit(0);
}

exit(0);
