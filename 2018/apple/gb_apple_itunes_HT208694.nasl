# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813110");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2018-4144", "CVE-2018-4101", "CVE-2018-4114", "CVE-2018-4118",
                "CVE-2018-4119", "CVE-2018-4120", "CVE-2018-4121", "CVE-2018-4122",
                "CVE-2018-4125", "CVE-2018-4127", "CVE-2018-4128", "CVE-2018-4129",
                "CVE-2018-4130", "CVE-2018-4161", "CVE-2018-4162", "CVE-2018-4163",
                "CVE-2018-4165", "CVE-2018-4113", "CVE-2018-4146", "CVE-2018-4117");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-02 10:32:52 +0530 (Mon, 02 Apr 2018)");
  script_name("Apple iTunes Security Updates(HT208694)-Windows");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error due to improper size validation..

  - Multiple memory corruption issues due to improper memory handling.

  - An array indexing issue in the handling of a function in javascript core.

  - A cross-origin issue existed with the fetch API.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to elevate privileges, exfiltrate data cross-origin,
  execute arbitrary code and lead to a denial of service condition.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.7.4 on Windows");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208694");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
ituneVer = infos['version'];
itunePath = infos['location'];

##12.7.4 == 12.7.4.76
if(version_is_less(version:ituneVer, test_version:"12.7.4.76"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.7.4", install_path:itunePath);
  security_message(data:report);
  exit(0);
}
exit(0);
