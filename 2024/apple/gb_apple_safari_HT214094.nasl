# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832900");
  script_version("2024-04-05T05:05:37+0000");
  script_cve_id("CVE-2024-1580");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-28 15:17:28 +0530 (Thu, 28 Mar 2024)");
  script_name("Apple Safari Security Update (HT214094)");

  script_tag(name:"summary", value:"Apple Safari is prone to an out-of-bounds
  write vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  write error in WebRTC component of Safari.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple Safari prior to version 17.4.1");

  script_tag(name:"solution", value:"Update to version 17.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214094");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^12\." && osVer !~ "^13\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos["version"];
safPath = infos["location"];

if(version_is_less(version:safVer, test_version:"17.4.1")) {
  report = report_fixed_ver(installed_version:safVer, fixed_version:"17.4.1", install_path:safPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
