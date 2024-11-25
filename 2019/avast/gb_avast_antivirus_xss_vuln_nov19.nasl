# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107746");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 15:03:00 +0000 (Wed, 06 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-09 19:30:43 +0100 (Sat, 09 Nov 2019)");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-18653");

  script_name("Avast Antivirus <= 19.3.2369 XSS Vulnerability - Windows");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_tag(name:"summary", value:"Avast Antivirus is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A Cross Site Scripting (XSS) issue exists in Avast AntiVirus.");

  script_tag(name:"impact", value:"The vulnerability allows an attacker to execute JavaScript code via an SSID Name
  in a Network Notification Popup.");

  script_tag(name:"affected", value:"Avast Antivirus before version 19.4.");

  script_tag(name:"solution", value:"Update to Avast Antivirus version 19.4 or later.");

  script_xref(name:"URL", value:"https://medium.com/@YoKoKho/5-000-usd-xss-issue-at-avast-desktop-antivirus-for-windows-yes-desktop-1e99375f0968");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"19.3.2369" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.4", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
