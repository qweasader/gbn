# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814834");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-5784");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-01 18:54:00 +0000 (Mon, 01 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-02-08 11:24:01 +0530 (Fri, 08 Feb 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to an unspecified remote security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inappropriate implementation
  in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to have unspecified impact on the affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 72.0.3626.96
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 72.0.3626.96
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/02/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"72.0.3626.96"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"72.0.3626.96", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
