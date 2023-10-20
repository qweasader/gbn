# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108394");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0437", "CVE-2015-0421", "CVE-2014-6549");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-02 12:08:03 +0530 (Mon, 02 Feb 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Feb 2015 (Linux)");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified flaws exist due to:

  - An error in the Hotspot JVM compiler related to code optimization.

  - An error in the Install component.

  - An error in the 'java.lang.ClassLoader getParent' function related to an
  improper permission check.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain escalated privileges, bypass sandbox restrictions and execute arbitrary
  code.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 25 and prior on
  Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72146");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.8") {
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.25")) {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}

exit(99);
