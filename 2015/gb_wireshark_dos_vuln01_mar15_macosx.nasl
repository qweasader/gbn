# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805487");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2015-2192", "CVE-2015-2190", "CVE-2015-2187");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-03-09 17:44:35 +0530 (Mon, 09 Mar 2015)");
  script_name("Wireshark Denial-of-Service Vulnerability-01 (Mar 2015) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to Integer overflow in
  the 'dissect_osd2_cdb_continuation' function in epan/dissectors/packet-scsi-osd.c
  script and a flaw in the ATN-CPDLC dissector and LLDP dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.4
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to version 1.12.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72940");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2015-06.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE))
{
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.3"))
{
  fix = "1.12.4";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + wirversion + '\nFixed Version:     ' + fix + '\n';
  security_message(port:0, data:report);
  exit(0);
}


