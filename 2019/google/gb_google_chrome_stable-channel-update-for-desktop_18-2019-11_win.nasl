# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815851");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-13724", "CVE-2019-13723");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-30 03:15:00 +0000 (Sat, 30 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-20 10:04:46 +0530 (Wed, 20 Nov 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_18-2019-11) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An use-after-free error in Bluetooth.

  - An out-of-bounds access error in Bluetooth.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to remotely execute code, leak sensitive data or cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 78.0.3904.108
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  78.0.3904.108 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/11/stable-channel-update-for-desktop_18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];
if(version_is_less(version:vers, test_version:"78.0.3904.108"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"78.0.3904.108", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
