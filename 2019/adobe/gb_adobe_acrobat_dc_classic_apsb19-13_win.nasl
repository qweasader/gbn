# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814862");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2019-7815");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-02-25 12:46:35 +0530 (Mon, 25 Feb 2019)");
  script_name("Adobe Acrobat DC (Classic Track) Security Updates (APSB19-13) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC Classic 2015 is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to leakage of sensitive data.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information which may aid further attacks.");

  script_tag(name:"affected", value:"Adobe Acrobat DC Classic 2015 version 2015.x
  before 2015.006.30475 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Classic 2015 version
  2015.006.30482 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-13.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

## 2015.006.30482 == 15.006.30482
if(version_is_less(version:vers, test_version:"15.006.30482")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.006.30482 (2015.006.30482)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
