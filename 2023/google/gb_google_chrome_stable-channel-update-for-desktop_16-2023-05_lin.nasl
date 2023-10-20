# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832126");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-2721", "CVE-2023-2722", "CVE-2023-2723", "CVE-2023-2724",
"CVE-2023-2725", "CVE-2023-2726");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 14:53:00 +0000 (Thu, 25 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-24 14:40:08 +0530 (Wed, 24 May 2023)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_16-2023-05)-Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Navigation.

  - Use after free in Autofill UI.

  - Use after free in DevTools.

  - Type Confusion in V8.

  - Use after free in Guest View.

  - Inappropriate implementation in WebApp Installs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct
  spoofing and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 113.0.5672.126 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  113.0.5672.126 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop_16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"113.0.5672.126"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"113.0.5672.126", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
