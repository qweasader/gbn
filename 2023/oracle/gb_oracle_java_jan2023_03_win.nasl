# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826783");
  script_version("2023-04-03T10:19:50+0000");
  script_cve_id("CVE-2023-21843");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 12:14:51 +0530 (Wed, 18 Jan 2023)");
  script_name("Oracle Java SE Security Update (jan2023) 03 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to an input validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input validation
  within the Sound component in Oracle Java SE.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to manipulate data.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u351 and earlier,
  11.0.17, 17.0.5, 19.0.1 and earlier on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2023.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.351") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.17") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.5") ||
   version_in_range(version:vers, test_version:"19.0", test_version2:"19.0.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch from vendor", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
