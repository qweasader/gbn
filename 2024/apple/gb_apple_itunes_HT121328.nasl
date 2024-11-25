# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834634");
  script_version("2024-10-04T15:39:55+0000");
  script_cve_id("CVE-2024-44193");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-10-04 15:39:55 +0000 (Fri, 04 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-03 07:37:39 +0530 (Thu, 03 Oct 2024)");
  script_name("Apple iTunes Security Update (HT121328)");

  script_tag(name:"summary", value:"Apple iTunes is prone to a privilege
  escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"The flaw exists due to a privilege
  escalation vulnerability in Apple iTunes.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to elevate their privileges.");

  script_tag(name: "affected" , value:"Apple iTunes prior to version 12.13.3");

  script_tag(name: "solution" , value:"Update to version 12.13.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121328");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.13.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.13.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
