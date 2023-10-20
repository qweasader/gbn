# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820098");
  script_version("2023-09-19T05:06:03+0000");
  script_cve_id("CVE-2022-28250", "CVE-2022-28251", "CVE-2022-28252", "CVE-2022-28253",
                "CVE-2022-28254", "CVE-2022-28255", "CVE-2022-28256", "CVE-2022-28257",
                "CVE-2022-28258", "CVE-2022-28259", "CVE-2022-28260", "CVE-2022-28261",
                "CVE-2022-28262", "CVE-2022-28263", "CVE-2022-28264", "CVE-2022-28265",
                "CVE-2022-28266", "CVE-2022-28267", "CVE-2022-28268", "CVE-2022-28239",
                "CVE-2022-28240", "CVE-2022-28241", "CVE-2022-28242", "CVE-2022-28243",
                "CVE-2022-27800", "CVE-2022-27802", "CVE-2022-24101", "CVE-2022-27785",
                "CVE-2022-27786", "CVE-2022-27787", "CVE-2022-27788", "CVE-2022-27790",
                "CVE-2022-27791", "CVE-2022-27792", "CVE-2022-27793", "CVE-2022-27794",
                "CVE-2022-27797", "CVE-2022-27798", "CVE-2022-27801", "CVE-2022-28231",
                "CVE-2022-28232", "CVE-2022-28233", "CVE-2022-28236", "CVE-2022-28237",
                "CVE-2022-28238", "CVE-2022-28245", "CVE-2022-28246", "CVE-2022-28248",
                "CVE-2022-28269", "CVE-2022-24102", "CVE-2022-24103", "CVE-2022-24104",
                "CVE-2022-27795", "CVE-2022-27796", "CVE-2022-27799", "CVE-2022-28230",
                "CVE-2022-28235", "CVE-2022-28249", "CVE-2022-27789", "CVE-2022-28247",
                "CVE-2022-28244", "CVE-2022-28234", "CVE-2022-28837", "CVE-2022-28838",
                "CVE-2022-35672");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-18 16:46:00 +0000 (Wed, 18 May 2022)");
  script_tag(name:"creation_date", value:"2022-04-29 16:38:19 +0530 (Fri, 29 Apr 2022)");
  script_name("Adobe Reader 2017 Security Update (APSB22-16) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Heap-based buffer overflow errors.

  - Missing support for integrity check.

  - Violation of secure design principles.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, escalate privileges and disclose sensitive information
  on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Reader 2017 versions 2017.012.30205
  and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe Reader 2017 to version
  2017.012.30227 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.012.30205")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.012.30227 (2017.012.30227)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
