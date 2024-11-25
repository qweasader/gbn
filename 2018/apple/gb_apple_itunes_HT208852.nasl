# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813513");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-4224", "CVE-2018-4225", "CVE-2018-4226", "CVE-2018-4232",
                "CVE-2018-4192", "CVE-2018-4214", "CVE-2018-4204", "CVE-2018-4246",
                "CVE-2018-4200", "CVE-2018-4188", "CVE-2018-4201", "CVE-2018-4218",
                "CVE-2018-4233", "CVE-2018-4199", "CVE-2018-4190", "CVE-2018-4222");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 14:26:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-06-06 11:01:42 +0530 (Wed, 06 Jun 2018)");
  script_name("Apple iTunes Security Updates (HT208852)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An authorization issue in state management.

  - A permissions issue in the handling of web browser cookies.

  - A race condition issue in locking.

  - A memory corruption issue in input validation.

  - A type confusion issue in memory handling.

  - A memory corruption issue in state management.

  - An inconsistent user interface issue in state management.

  - Multiple memory corruption issues in memory handling.

  - A buffer overflow issue in memory handling.

  - An out-of-bounds read issue in input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to read a persistent device identifier, modify the state of the
  Keychain, view sensitive user information, overwrite cookies, execute arbitrary
  code, crash Safari, spoof address bar and leak sensitive data.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.7.5");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.7.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208852");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ituneVer = infos['version'];
iPath = infos['location'];

if(version_is_less(version:ituneVer, test_version:"12.7.5"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.7.5", install_path:iPath);
  security_message(data:report);
  exit(0);
}
exit(0);
