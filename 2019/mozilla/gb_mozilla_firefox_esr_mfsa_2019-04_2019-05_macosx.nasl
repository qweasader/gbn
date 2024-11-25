# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814930");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-1835", "CVE-2019-5785", "CVE-2018-1833");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 15:56:13 +0530 (Wed, 13 Feb 2019)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2019-04, MFSA2019-05) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A use-after-free vulnerability in the Skia library can occur when
    creating a path, leading to a potentially exploitable crash.

  - An integer overflow vulnerability in the Skia library can occur after
    specific transform operations, leading to a potentially exploitable crash

  - Cross-origin images can be read from a canvas element in violation
    of the same-origin policy using the transferFromImageBitmap method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 60.5.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 60.5.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-05");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"60.5.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"60.5.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(99);
