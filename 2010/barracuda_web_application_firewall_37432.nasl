# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:barracuda:web_application_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100420");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Barracuda Web Application Firewall 660 'cgi-mod/index.cgi' Multiple HTML Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37432");
  script_xref(name:"URL", value:"http://www.barracudanetworks.com/ns/products/web-site-firewall-overview.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("barracuda_web_application_firewall_detect.nasl");
  script_mandatory_keys("barracuda_waf/installed");

  script_tag(name:"summary", value:"The Barracuda Web Application Firewall 660 is prone to multiple HTML-
  injection vulnerabilities.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would execute in the context of the affected
  site, potentially allowing the attacker to steal cookie-based authentication credentials or to control how the site
  is rendered to the user. Other attacks are also possible.");

  script_tag(name:"affected", value:"The Barracuda Web Application Firewall 660 firmware 7.3.1.007 is vulnerable.
  Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_equal(version: version, test_version: "7.3.1.007")) {
  security_message(port:port);
  exit(0);
}

exit(0);