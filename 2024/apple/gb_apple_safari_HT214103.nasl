# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832978");
  script_version("2024-07-01T05:05:39+0000");
  script_cve_id("CVE-2024-27844", "CVE-2024-27834", "CVE-2024-27838", "CVE-2024-27808",
                "CVE-2024-27850", "CVE-2024-27833", "CVE-2024-27851", "CVE-2024-27830",
                "CVE-2024-27820");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 16:58:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 12:24:30 +0530 (Tue, 14 May 2024)");
  script_name("Apple Safari Security Update (HT214103)");

  script_tag(name:"summary", value:"Apple Safari is prone to an unknown
  vulnerability.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"The flaw exists due to an unknown
  vulnerability in Apple Safari.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to bypass pointer authentication.");

  script_tag(name: "affected" , value:"Apple Safari prior to version 17.5");

  script_tag(name: "solution" , value:"Update to version 17.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214103");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"17.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
