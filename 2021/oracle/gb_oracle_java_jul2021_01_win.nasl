# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818168");
  script_version("2023-04-03T10:19:50+0000");
  script_cve_id("CVE-2021-2341", "CVE-2021-2369");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-23 19:26:00 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-28 15:39:44 +0530 (Wed, 28 Jul 2021)");
  script_name("Oracle Java SE Security Update (jul2021) 01 - Windows");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Oracle.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple errors in
  'Libraries' and 'Networking' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to have an impact on integrity and confidentiality.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u301 (1.7.0.301)
  and earlier, 8u291 (1.8.0.291) and earlier, 11.0.11 and earlier, 16.0.1 and earlier on
  Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2021.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.291") ||
   version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.301") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.11") ||
   version_in_range(version:vers, test_version:"16.0", test_version2:"16.0.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
