# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:winscp:winscp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834214");
  script_version("2024-07-05T15:38:46+0000");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-07-05 15:38:46 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-06-27 11:38:58 +0530 (Thu, 27 Jun 2024)");
  script_name("WinSCP Terrapin Vulnerability - Windows");

  script_tag(name:"summary", value:"WinSCP is prone to a Terrapin
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  validation of integrity check value in the SSH protocol.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass integrity checks such that some packets are omitted (from the
  extension negotiation message), and a client and server may consequently end
  up with a connection for which some security features have been downgraded
  or disabled.");

  script_tag(name:"affected", value:"WinSCP prior to version 6.2.2 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 6.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://winscp.net/tracker/2246");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_winscp_detect_win.nasl");
  script_mandatory_keys("WinSCP/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"6.2.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.2.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
