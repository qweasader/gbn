# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100308");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4554");

  script_name("Snitz Forums 2000 Cross Site Scripting and HTML Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36710");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("snitz_forums_2000_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("snitzforums/detected");

  script_tag(name:"summary", value:"Snitz Forums 2000 is prone to a cross-site scripting vulnerability and
  an HTML-injection vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of
  the affected site, potentially allowing the attacker to steal cookie-based authentication credentials
  and to control how the site is rendered to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"Snitz Forums 2000 3.4.07 is vulnerable, other versions may also
  be affected.");

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

port = http_get_port(default:80);
if(!version = get_kb_item(string("www/", port, "/SnitzForums")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(version_is_equal(version: vers, test_version: "3.4.07")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
