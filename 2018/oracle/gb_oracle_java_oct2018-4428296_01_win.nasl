# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814097");
  script_version("2023-04-03T10:19:50+0000");
  script_cve_id("CVE-2018-3169");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:33:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-10-17 11:39:28 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Java SE Privilege Escalation Vulnerability (oct2018-4428296)-Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Hotspot component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.7.0 to 1.7.0.191 and
  1.8.0 to 1.8.0.182 and 11 on Windows.");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(1\.[78]|11)") {
  if((version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.191")) ||
     (version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.182")) ||
     (version_is_equal(version:vers, test_version:"11"))) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
