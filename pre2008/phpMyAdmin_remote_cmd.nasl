# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: phpMyAdmin team

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15478");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2630");
  script_xref(name:"OSVDB", value:"10715");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpMyAdmin remote command execution");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/12813/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11391");

  script_tag(name:"summary", value:"The remote web server contains a PHP application that may allow
  arbitrary command execution.");
  script_tag(name:"insight", value:"According to its banner, the remote version of phpMyAdmin is vulnerable
  to an unspecified vulnerability in the MIME-based transformation system
  with 'external' transformations that may allow arbitrary command
  execution. Successful exploitation requires that PHP's 'safe_mode' be
  enabled.");
  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 2.6.0-pl2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ereg( pattern:"(2\.[0-5]\..*|2\.6\.0$|2\.6\.0-pl1)", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.0-pl2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
