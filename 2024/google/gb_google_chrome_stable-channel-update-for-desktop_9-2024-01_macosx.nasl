# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832779");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2024-0333");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-18 19:39:00 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-11 11:13:23 +0530 (Thu, 11 Jan 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_9-2024-01) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to a data
  validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient data
  validation in Extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to install a malicious extension via a crafted HTML page.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  120.0.6099.216 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 120.0.6099.216 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_9.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"120.0.6099.216")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"120.0.6099.216", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
