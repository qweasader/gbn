# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800684");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7100");
  script_name("DotNetNuke 4.4.1 - 4.8.4 Identity Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_http_detect.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused due improper validation of a user
  identity.");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass
  security restrictions via unknown vectors related to a 'unique id' and impersonate other users and
  possibly gain elevated pivileges.");

  script_tag(name:"affected", value:"DotNetNuke versions 4.4.1 through 4.8.4.");

  script_tag(name:"solution", value:"Update to version 4.9.0 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31145");
  script_xref(name:"URL", value:"http://www.dotnetnuke.com/News/SecurityPolicy/Securitybulletinno21/tabid/1174/Default.aspx");

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

if( version_in_range( version:vers, test_version:"4.4.1", test_version2:"4.8.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.9.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
