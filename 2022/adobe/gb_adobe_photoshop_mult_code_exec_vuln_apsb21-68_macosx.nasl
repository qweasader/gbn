# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826527");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2021-36065", "CVE-2021-36066");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 13:57:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-15 18:16:20 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Photoshop Multiple Code Execution Vulnerabilities (APSB21-68) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Photoshop is prone to multiple remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An out-of-bounds write error.

  - A heap-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution on target system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2020 prior to 21.2.11 and
  Adobe Photoshop 2021 prior to 22.5.");

  script_tag(name:"solution", value:"Update to Adobe Photoshop 2020 21.2.11
  or Adobe Photoshop 2021 22.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-68.html");

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^21\.")
{
  if(version_is_less(version:vers, test_version:"21.2.11")) {
    fix = "21.2.11";
    installed_ver = "Adobe Photoshop 2020";
  }
}

else if(vers =~ "^22\.")
{
  if(version_is_less(version:vers, test_version:"22.5"))
  {
    fix = "22.5";
    installed_ver = "Adobe Photoshop 2021";
  }
}
if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
