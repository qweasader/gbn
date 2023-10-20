# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815687");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2019-16449", "CVE-2019-16456", "CVE-2019-16457", "CVE-2019-16458",
                "CVE-2019-16461", "CVE-2019-16465", "CVE-2019-16450", "CVE-2019-16454",
                "CVE-2019-16445", "CVE-2019-16448", "CVE-2019-16452", "CVE-2019-16459",
                "CVE-2019-16464", "CVE-2019-16451", "CVE-2019-16462", "CVE-2019-16446",
                "CVE-2019-16455", "CVE-2019-16460", "CVE-2019-16463", "CVE-2019-16444",
                "CVE-2019-16453");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-30 17:01:00 +0000 (Mon, 30 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-12 12:24:08 +0530 (Thu, 12 Dec 2019)");
  script_name("Adobe Acrobat 2017 Security Updates(apsb19-55) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat 2017 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to following
  errors,

  - An out-of-bounds read.

  - An out-of-bounds write.

  - A use after free.

  - A heap overflow.

  - A buffer error.

  - Untrusted Pointer Dereference.

  - Binary Planting (default folder privilege escalation).

  - A Security Bypass.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain escalated privileges, get access to potentially sensitive
  information and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Acrobat 2017 prior to version
  2017.011.30156 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat 2017 version
  2017.011.30156 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## 2017.011.30156 == 17.011.30156
if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30155")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30156 (2017.011.30156)", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
