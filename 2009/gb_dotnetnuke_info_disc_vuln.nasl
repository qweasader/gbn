# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800153");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4109");
  script_name("DotNetNuke 4.0 - 5.1.4 Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_http_detect.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DotNetNuke is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to install wizard insecurely displaying
  certain pages containing version information to an anonymous user.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker obtain sensitive
  information and attacker can use this information for further attacks.");

  script_tag(name:"affected", value:"DotNetNuke versions 4.0 through 5.1.4.");

  script_tag(name:"solution", value:"Update to version 5.2.0 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37480");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37139");
  script_xref(name:"URL", value:"http://www.dotnetnuke.com/News/SecurityPolicy/securitybulletinno30/tabid/1449/Default.aspx");

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

if( version_in_range( version:vers, test_version:"4.0", test_version2:"5.1.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
