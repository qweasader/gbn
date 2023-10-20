# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832187");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-5346");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-07 03:18:00 +0000 (Sat, 07 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-06 11:25:37 +0530 (Fri, 06 Oct 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2023-10) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to heap corruption
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a heap corruption
  vulnerability in Google Chrome.");

  script_tag(name:"impact", value:"Successful exploitation would allow
  attackers to conduct heap buffer overflow attacks on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  117.0.5938.149 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 117.0.5938.149/.150 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/10/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"117.0.5938.149")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"117.0.5938.149/.150", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);