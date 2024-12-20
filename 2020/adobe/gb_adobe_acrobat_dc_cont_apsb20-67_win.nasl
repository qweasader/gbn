# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817814");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2020-24428", "CVE-2020-24429", "CVE-2020-24430", "CVE-2020-24431",
                "CVE-2020-24432", "CVE-2020-24433", "CVE-2020-24434", "CVE-2020-24435",
                "CVE-2020-24436", "CVE-2020-24437", "CVE-2020-24438", "CVE-2020-24439",
                "CVE-2020-24427", "CVE-2020-24426");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 03:38:00 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 16:36:59 +0530 (Wed, 04 Nov 2020)");
  script_name("Adobe Acrobat DC (Continuous) Security Update (APSB20-67) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat DC (Continuous Track) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due,

  - An improper access control error.

  - An improper input validation error.

  - Signature validation bypass error.

  - Signature verification bypass error.

  - A security feature bypass error.

  - A heap-based buffer overflow error.

  - A race condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to escalate privilege, execute arbitrary code or javascript, disclose
  sensitive information and conduct dynamic library injection.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous Track) prior
  to version 2020.013.20064.");

  script_tag(name:"solution", value:"Update Adobe Acrobat DC (Continuous)
  to version 2020.013.20064 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-67.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.012.20048")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.013.20064(2020.013.20064)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
