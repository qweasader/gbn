# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815816");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-15903", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759",
                "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763",
                "CVE-2019-11764");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)");
  script_tag(name:"creation_date", value:"2019-10-25 15:57:09 +0530 (Fri, 25 Oct 2019)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2019-32, MFSA2019-35) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A heap overflow error in expat library in XML_GetCurrentLineNumber.

  - An use-after-free error when creating index updates in IndexedDB.

  - A memory corruption error in the accessibility engine.

  - Multiple stack buffer overflow errors in HKDF output and WebRTC networking.

  - An unintended access to a privileged JSONView object.

  - The document.domain-based origin isolation has same-origin-property violation.

  - Failure to correctly handle null bytes when processing HTML entities.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  cause denial of service, run arbitrary code and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 68.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 68.2
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-35/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"68.2"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"68.2", install_path:tbPath);
  security_message(data:report);
  exit(0);
}

exit(99);
