# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826975");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-26417", "CVE-2023-26418", "CVE-2023-26419", "CVE-2023-26420",
                "CVE-2023-26422", "CVE-2023-26423", "CVE-2023-26405", "CVE-2023-26406",
                "CVE-2023-26407", "CVE-2023-26408", "CVE-2023-26424", "CVE-2023-26425",
                "CVE-2023-26421", "CVE-2023-26395", "CVE-2023-26396", "CVE-2023-26397");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-13 02:51:00 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-14 17:10:30 +0530 (Fri, 14 Apr 2023)");
  script_name("Adobe Reader Classic 2020 Security Update (APSB23-24) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper input validation.

  - An improper access control error.

  - An integer underflow error.

  - Multiple out-of-bounds read or write errors.

  - Violation of secure design principles.

  - Multiple use after free errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, execute arbitrary code and cause memory leak on an
  affected system.");

  script_tag(name:"affected", value:"Adobe Reader Classic 2020 version
  prior to 20.005.30467 on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe Reader Classic 2020 to
  version 20.005.30467 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.005.30441"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.005.30467(2020.005.30467)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
