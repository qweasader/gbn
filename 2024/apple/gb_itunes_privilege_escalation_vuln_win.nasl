# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128007");
  script_version("2024-04-19T05:05:37+0000");
  script_cve_id("CVE-2023-42938");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-04-19 05:05:37 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 12:00:00 +0530 (Mon, 15 Apr 2024)");
  script_name("Apple iTunes < 12.13.1 Local Privilege Escalation Vulnerability (HT214091) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214091");

  script_tag(name:"summary", value:"Apple iTunes is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a logic issue.");

  script_tag(name:"impact", value:"Successful exploitation with an unknown input leads to a local
  privilege escalation vulnerability.");

  script_tag(name:"affected", value:"Apple iTunes before 12.13.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 12.13.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.13.1"))  {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.13.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
