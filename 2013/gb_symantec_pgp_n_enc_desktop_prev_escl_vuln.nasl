# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803886");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-1610");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-03 17:08:26 +0530 (Tue, 03 Sep 2013)");
  script_name("Symantec PGP Desktop and Encryption Desktop Local Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Symantec PGP/Encryption Desktop is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version 10.3.0 MP3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"insight", value:"Flaw is due to an unquoted search path in the RDDService.");

  script_tag(name:"affected", value:"Symantec PGP Desktop 10.0.x, 10.1.x, and 10.2.x
  Symantec Encryption Desktop 10.3.0 prior to 10.3.0 MP3.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated attacker to execute
  arbitrary code, gain escalated privileges.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61489");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52219");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop_or_EncryptionDesktop/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:symantec:pgp_desktop", "cpe:/a:symantec:encryption_desktop");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.3.0.9306")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"10.0 - 10.3.0.9306", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
