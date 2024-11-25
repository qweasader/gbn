# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:7-zip:7-zip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834220");
  script_version("2024-09-18T05:05:35+0000");
  script_cve_id("CVE-2023-40481");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-18 05:05:35 +0000 (Wed, 18 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-07-09 12:56:05 +0530 (Tue, 09 Jul 2024)");
  script_name("7-Zip RCE Vulnerability - Windows");

  script_tag(name:"summary", value:"7zip is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  write error in 7zip.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"7zip version prior to 23.00 on Windows.");

  script_tag(name:"solution", value:"Update to version 23.00.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sevenzip/patches/417/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"23.00")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"23.00", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
