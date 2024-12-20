# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817074");
  script_version("2024-02-22T05:06:55+0000");
  script_cve_id("CVE-2020-6509");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-22 05:06:55 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 18:15:00 +0000 (Fri, 18 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 09:37:26 +0530 (Fri, 03 Jul 2020)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Use-After-Free In Extensions Vulnerability (Jun 2020) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to a use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to use-after-free error in extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute code on
  the host.");

  script_tag(name:"affected", value:"Google Chrome before 83.0.4103.116.");

  script_tag(name:"solution", value:"Update to version 83.0.4103.116 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/06/stable-channel-update-for-desktop_22.html");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_category(ACT_GATHER_INFO);
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

if(version_is_less(version:vers, test_version:"83.0.4103.116")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"83.0.4103.116", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
