# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113107");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-02-08 12:15:18 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-24 21:50:00 +0000 (Sat, 24 Feb 2018)");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-6168", "CVE-2016-6169");

  script_name("Foxit Reader 7.3.4.311 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Use-after-free / Buffer overflow vulnerability in Foxit Reader can be exploited via a crafted PDF file.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause a Denial of Service or execute arbitrary code on the target host.");
  script_tag(name:"affected", value:"Foxit Reader through version 7.3.4.311");
  script_tag(name:"solution", value:"Update to Foxit Reader 8.0 or above.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-16-021");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  exit(0);
}

CPE = "cpe:/a:foxitsoftware:reader";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version: vers, test_version: "7.3.4.311" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "8.0", install_path: path );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
