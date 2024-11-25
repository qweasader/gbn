# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16162");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0378");
  script_name("Horde 3.0 XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/35724/H2005-01.txt.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12255");

  script_tag(name:"solution", value:"Upgrade to Horde version 3.0.1 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Horde version 3.0, which
suffers from two cross site scripting vulnerabilities.

Through specially crafted GET requests to the remote host, an attacker can cause a third party user to unknowingly
run arbitrary Javascript code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"3.0" ) ||
    version_is_equal( version:vers, test_version:"3.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.1");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
