# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800558");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6657", "CVE-2008-6658", "CVE-2008-6659");
  script_name("Simple Machines Forum Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32139");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6993");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7011");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46343");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMF/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute malicious arbitrary
  codes in the context of the SMF web application to gain administrative
  privileges, install malicious components into the forum context or can
  cause directory traversal attacks also.");

  script_tag(name:"affected", value:"Simple Machines Forum version 1.0 to 1.0.14.

  Simple Machines Forum version 1.1 to 1.1.6.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Lack of access control and validation check while performing certain
  HTTP requests which lets the attacker perform certain administrative commands.

  - Lack of validation check for the 'theme_dir' settings before being
  used which causes arbitrary code execution from local resources.

  - Crafted avatars are being allowed for code execution.");

  script_tag(name:"solution", value:"Update your Simple Machines Forum version to 1.1.7 or later.");

  script_tag(name:"summary", value:"Simple Machines Forum is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("http_func.inc");
include("port_service_func.inc");

httpPort = http_get_port(default:80);
ver = get_kb_item("www/" + httpPort + "/SMF");
ver = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(ver[1] == NULL){
  exit(0);
}

if((version_in_range(version:ver[1], test_version:"1.0", test_version2:"1.0.14"))||
   (version_in_range(version:ver[1], test_version:"1.1", test_version2:"1.1.6"))){
 security_message(port:httpPort, data:"The target host was found to be vulnerable.");
 exit(0);
}

exit(99);
