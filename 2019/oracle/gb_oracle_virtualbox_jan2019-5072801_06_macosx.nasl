# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814657");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2019-2448", "CVE-2019-2508", "CVE-2019-2509", "CVE-2019-2548",
                "CVE-2019-2505", "CVE-2019-2506", "CVE-2019-2500", "CVE-2019-2555",
                "CVE-2019-2446", "CVE-2019-2526", "CVE-2019-2527", "CVE-2019-2524",
                "CVE-2019-2525", "CVE-2019-2522", "CVE-2019-2523", "CVE-2019-2520",
                "CVE-2019-2521", "CVE-2019-2504", "CVE-2019-2556", "CVE-2019-2554",
                "CVE-2019-2553", "CVE-2019-2552", "CVE-2019-2450", "CVE-2019-2451",
                "CVE-2019-2501", "CVE-2019-2511");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-16 15:28:28 +0530 (Wed, 16 Jan 2019)");
  script_name("Oracle VirtualBox Security Updates (jan2019-5072801) 06 - Mac OS X");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified errors exist in the 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to affect confidentiality, availability and integrity via
  unknown vectors.");

  script_tag(name:"affected", value:"VirtualBox versions Prior to 5.2.24
  and 6.x prior to 6.0.2 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox 5.2.24 or
  6.0.2  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
virtualVer = infos['version'];
path = infos['location'];

if(version_is_less(version:virtualVer, test_version:"5.2.22")){
  fix = "5.2.22";
}

else if(virtualVer =~ "^6\.0")
{
  if(version_is_less(version:virtualVer, test_version:"6.0.2")){
    fix = "6.0.2";
  }
}

if(fix)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
