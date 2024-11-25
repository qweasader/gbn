# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813852");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2018-12808", "CVE-2018-12799");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-16 11:03:52 +0530 (Thu, 16 Aug 2018)");
  script_name("Adobe Acrobat DC (Continuous Track) Multiple Arbitrary Code Execution Vulnerabilities (APSB18-29) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Continuous Track) is prone to multiple arbitrary code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An untrusted pointer dereference error.

  - An out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct arbitrary code execution in the context of the current
  user.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous Track) 2018.011.20055
  and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat DC Continuous
  version 2018.011.20058 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb18-29.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

##2018.011.20058 == 18.011.20058
if(version_is_less(version:vers, test_version:"18.011.20058")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"18.011.20058 (2018.011.20058)", install_path:path);
  security_message(data:report);
  exit(0);
}
