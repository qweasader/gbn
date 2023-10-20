# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106585");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-02-09 11:28:49 +0700 (Thu, 09 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-7937");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Schneider Electric Modicon M340 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_schneider_modbus_detect.nasl");
  script_mandatory_keys("schneider_electric/detected", "schneider_electric/product", "schneider_electric/version");

  script_tag(name:"summary", value:"Schneider Electric Modicon M340 devices are prone to a buffer overflow
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in the GoAhead Web Server on Schneider Electric
Modicon M340 devices allows remote attackers to execute arbitrary code via a long password in HTTP Basic
Authentication data.");

  script_tag(name:"impact", value:"A unauthenticated attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Schneider Electric BMXNOC0401 prior version 2.09, BMXNOE0100 prior version
3.10, BMXNOE0100H prior version 3.10, BMXNOE0110 prior version 6.30, BMXNOE0110H prior version 6.30, BMXNOR0200
prior version 1.70, BMXNOR0200H prior version 1.70, BMXP342020, BMXP342020H, BMXP342030, BMXP3420302, BMXP3420302H,
BMXPRA0100 all prior version 2.80.");

  script_tag(name:"solution", value:"Upgrade to fixed versions according the vendors advisory.");

  script_xref(name:"URL", value:"http://www.schneider-electric.com/ww/en/download/document/SEVD-2015-344-01");

  exit(0);
}

include("version_func.inc");


prod = get_kb_item("schneider_electric/product");
if (!prod || prod !~ "^BMX")
  exit(0);

version = get_kb_item("schneider_electric/version");
if (!version)
  exit(0);

if (prod =~ "^BMX\s*NOC\s*0401$") {
  if (version_is_less(version: version, test_version: "2.09")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.09");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (prod =~ "^BMX\s*NOE\s*0100$" || prod =~ "^BMX\s*NOE\s*0100H$") {
  if (version_is_less(version: version, test_version: "3.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.10");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (prod =~ "^BMX\s*NOE\s*0110$" || prod =~ "^BMX\s*NOE\s*0110H$") {
  if (version_is_less(version: version, test_version: "6.30")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.30");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (prod =~ "^BMX\s*NOR\s*0200$" || prod =~ "^BMX\s*NOR\s*0200H$") {
  if (version_is_less(version: version, test_version: "1.70")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.70");
    security_message(port: 0, data: report);
  }
  exit(0);
}

if (prod =~ "^BMX\s*P34\s*2020$" || prod =~ "^BMX\s*P34\s*2020H$" || prod =~ "^BMX\s*P34\s*2030$" || prod =~ "^BMX\s*P34\s*20302$" ||
    prod =~ "^BMX\s*P34\s*20302H$" || prod =~ "^BMX\s*PRA\s*0100$") {
  if (version_is_less(version: version, test_version: "2.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.8");
    security_message(port: 0, data: report);
  }
  exit(0);
}

exit(99);
