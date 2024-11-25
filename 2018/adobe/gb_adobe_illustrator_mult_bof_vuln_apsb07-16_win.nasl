# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813496");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2007-2244", "CVE-2007-2365");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-07-12 15:32:37 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod", value:"30"); ## Solution is Mitigation
  script_name("Adobe Illustrator Multiple Buffer Overflow Vulnerabilities (APSB07-16) - Windows");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple buffer
  overflow errors while opening malicious BMP, DIB, RLE, or PNG files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator CS3 on Windows.");

  script_tag(name:"solution", value:"Patch is available as a solution from
  vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb07-16.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_win.nasl");
  script_mandatory_keys("Adobe/Illustrator/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^13\.") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply Mitigation", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
