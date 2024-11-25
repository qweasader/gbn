# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834255");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2024-34140");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 20:15:11 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-12 17:23:30 +0530 (Fri, 12 Jul 2024)");
  script_name("Adobe Bridge Memory Leak Vulnerability (APSB24-51_1) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Bridge is prone to a memory leak
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error in Bridge.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Bridge version 14.0.4 and prior on
  Mac OS X.");

  script_tag(name:"solution", value:"Update to version 14.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb24-51.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Bridge/CC/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"14.0", test_version2:"14.0.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.1.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
