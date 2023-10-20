# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817562");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2021-21106", "CVE-2021-21107", "CVE-2021-21108", "CVE-2021-21109",
                "CVE-2021-21110", "CVE-2021-21111", "CVE-2021-21112", "CVE-2021-21113",
                "CVE-2020-16043", "CVE-2021-21114", "CVE-2020-15995", "CVE-2021-21115",
                "CVE-2021-21116");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-28 20:49:00 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-07 17:48:08 +0530 (Thu, 07 Jan 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2021-01) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in autofill.

  - Use after free in drag and drop.

  - Use after free in media.

  - Use after free in payments.

  - Use after free in safe browsing.

  - Insufficient policy enforcement in WebUI.

  - Use after free in Blink.

  - Heap buffer overflow in Skia.

  - Insufficient data validation in networking.

  - Use after free in audio.

  - Out of bounds write in V8.

  - Heap buffer overflow in audio.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 87.0.4280.141 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  87.0.4280.141 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"87.0.4280.141"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"87.0.4280.141", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
