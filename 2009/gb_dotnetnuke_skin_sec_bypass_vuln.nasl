# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800685");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7102");
  script_name("DotNetNuke 2.0 - 4.8.4 Skin Files Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_http_detect.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused due improper validation of user data
  passed via unspecified parameters before being used to load skin files.");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to gain
  administrative privileges or compromise the affected system.");

  script_tag(name:"affected", value:"DotNetNuke versions 2.0 through 4.8.4.");

  script_tag(name:"solution", value:"Update to version 4.9.0 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31145");
  script_xref(name:"URL", value:"http://www.dotnetnuke.com/News/SecurityPolicy/Securitybulletinno23/tabid/1176/Default.aspx");

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

if( version_in_range( version:vers, test_version:"2.0", test_version2:"4.8.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.9.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
