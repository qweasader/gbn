# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113822");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-06-23 09:32:25 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-29921");

  script_name("Python < 3.9.5 Authentication Bypass Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists in the ipaddress library,
  which mishandles leading zero characters in the octets of an IP address string.
  This would allow an attacker to bypass IP-based access control.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  gain unauthorized access to the target system.");

  script_tag(name:"affected", value:"Python through version 3.9.4.");

  script_tag(name:"solution", value:"Update to version 3.9.5 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue36384");
  script_xref(name:"URL", value:"https://docs.python.org/3/whatsnew/changelog.html#python-3-9-5-final");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
