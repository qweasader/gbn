# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106630");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-03-03 14:24:24 +0700 (Fri, 03 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-24 16:29:00 +0000 (Mon, 24 Dec 2018)");

  script_cve_id("CVE-2017-6017");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Schneider Electric Modicon M340 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_schneider_modbus_detect.nasl");
  script_mandatory_keys("schneider_electric/detected", "schneider_electric/product", "schneider_electric/version");

  script_tag(name:"summary", value:"Schneider Electric Modicon M340 devices are prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"During communication between the operator and PLC using function code 0x5A
  of Modbus, it is possible to send a specially crafted set of packets to the PLC and cause it to freeze, requiring
  the operator to physically press the reset button of the PLC in order to recover.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability may render the device
  unresponsive requiring a physical reset of the PLC.");

  script_tag(name:"affected", value:"Schneider Electric BMXNOC0401, BMXNOE0100, BMXNOE0110, BMXNOE0110H,
  BMXNOR0200H, BMXP341000, BMXP342000, BMXP3420102, BMXP3420102CL, BMXP342020, BMXP342020H, BMXP342030,
  BMXP3420302, BMXP3420302H and BMXP342030H prior to firmware version 2.9.");

  script_tag(name:"solution", value:"Upgrade to firmware version 2.9 or later.");

  script_xref(name:"URL", value:"http://www.schneider-electric.com/en/download/document/SEVD-2017-048-02/");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-054-03");

  exit(0);
}

include("version_func.inc");

prod = get_kb_item("schneider_electric/product");
if (!prod || prod !~ "^BMX")
  exit(0);

version = get_kb_item("schneider_electric/version");
if (!version)
  exit(0);

if (prod =~ "^BMX\s*NOC\s*0401$" || prod =~ "^BMX\s*NOE\s*0100$" || prod =~ "^BMX\s*NOE\s*0110$" || prod =~ "^BMX\s*NOE\s*0110H$" ||
    prod =~ "^BMX\s*NOR\s*0200H$" || prod =~ "^BMX\s*P34\s*1000$" || prod =~ "^BMX\s*P34\s*2000$" || prod =~ "^BMX\s*P34\s*20102$" ||
    prod =~ "^BMX\s*P34\s*20102CL$" || prod =~ "^BMX\s*P34\s*2020$" || prod =~ "^BMX\s*P34\s*2020H$" || prod =~ "^BMX\s*P34\s*2030$" ||
    prod =~ "^BMX\s*P34\s*20302$" || prod =~ "^BMX\s*P34\s*20302H$" || prod =~ "^BMX\s*P34\s*2030H$") {
  if (version_is_less(version: version, test_version: "2.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.9");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
