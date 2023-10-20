# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813155");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 14:12:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-25 11:34:56 +0530 (Wed, 25 Apr 2018)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-14847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mikrotik RouterOS 'Winbox Service' Information Disclosure Vulnerability - Version Check");

  script_tag(name:"summary", value:"Mikrotik RouterOS is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the winbox service of
  routeros which allows remote users to download a user database file without successful
  authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to connect
  to the WinBox port and download a user database file. The remote user can then log in and take
  control of the router.");

  script_tag(name:"affected", value:"MikroTik Router OS versions 6.29 through 6.42, 6.43rcx prior to
  6.43rc4.");

  script_tag(name:"solution", value:"Update to version 6.42.1, 6.43rc4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=133533");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_in_range(version:vers, test_version:"6.29", test_version2:"6.42")) {
  fix = "6.42.1";
} else if (vers == "6.43rc1" || vers == "6.43rc2" || vers == "6.43rc3") {
  fix = "6.43rc4";
}

if (fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit( 0 );
}

exit(99);