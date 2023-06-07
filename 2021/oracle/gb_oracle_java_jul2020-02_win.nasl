# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118164");
  script_version("2023-04-03T10:19:50+0000");
  script_cve_id("CVE-2020-14578", "CVE-2020-14579");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2021-08-25 09:18:34 +0200 (Wed, 25 Aug 2021)");
  script_name("Oracle Java SE Security Updates(jul2020) 02 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to errors in the 'Libraries'
  component.");

  script_tag(name:"impact", value:"Successful attacks of these vulnerabilities can result in
  unauthorized ability to cause a partial denial of service.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u261 (1.7.0.261) and earlier, 8u251
  (1.8.0.251) and earlier on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:oracle:jre", "cpe:/a:sun:jre" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"1.7.0", test_version2:"1.7.0.261" ) ||
  version_in_range( version:vers, test_version:"1.8.0", test_version2:"1.8.0.251" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Apply the patch", install_path:path );
  security_message( data:report );
  exit( 0 );
}

exit( 99 );
