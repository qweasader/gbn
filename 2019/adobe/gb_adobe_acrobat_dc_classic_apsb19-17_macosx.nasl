# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814788");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2019-7061", "CVE-2019-7109", "CVE-2019-7110", "CVE-2019-7114",
                "CVE-2019-7115", "CVE-2019-7116", "CVE-2019-7121", "CVE-2019-7122",
                "CVE-2019-7123", "CVE-2019-7127", "CVE-2019-7111", "CVE-2019-7118",
                "CVE-2019-7119", "CVE-2019-7120", "CVE-2019-7124", "CVE-2019-7117",
                "CVE-2019-7128", "CVE-2019-7088", "CVE-2019-7112", "CVE-2019-7113",
                "CVE-2019-7125");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-04-11 11:09:50 +0530 (Thu, 11 Apr 2019)");
  script_name("Adobe Acrobat DC (Classic Track) Security Updates (APSB19-17) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat DC Classic 2015 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Type confusionerrors.

  - Use After Free errors.

  - Heap Overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and run arbitrary code in context of
  current user.");

  script_tag(name:"affected", value:"Adobe Acrobat DC Classic 2015 version 2015.x
  before 2015.006.30493 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Classic 2015 version
  2015.006.30493 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_macosx.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

## 2015.006.30493 == 15.006.30493
if(version_is_less(version:vers, test_version:"15.006.30493")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.006.30493 (2015.006.30493)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
