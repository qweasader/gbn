# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832559");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2023-4572");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 04:15:00 +0000 (Fri, 01 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 11:03:05 +0530 (Fri, 27 Oct 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_29-2023-08) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an use-after-free
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an use-after-free in
  MediaStream.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to potentially exploit heap corruption via a crafted HTML page to
  cause a memory leak on an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  116.0.5845.140 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  116.0.5845.140 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/08/stable-channel-update-for-desktop_29.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"116.0.5845.140")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"116.0.5845.140", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
