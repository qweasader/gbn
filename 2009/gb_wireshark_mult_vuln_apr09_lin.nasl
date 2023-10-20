# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800397");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1210", "CVE-2009-1266", "CVE-2009-1267", "CVE-2009-1268",
                "CVE-2009-1269");
  script_name("Wireshark Multiple Unspecified Vulnerabilities - Apr09 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34457");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34778");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34542");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Apr/1022027.html");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.9.6 to 1.0.6 on Linux");

  script_tag(name:"insight", value:"- Error exists while processing PN-DCP packet with format string specifiers
  in PROFINET/DCP (PN-DCP) dissector.

  - Error in unknown impact and attack vectors.

  - Error in Lightweight Directory Access Protocol (LDAP) dissector when
  processing unknown attack vectors.

  - Error in Check Point High-Availability Protocol (CPHAP) when processing
  crafted FWHA_MY_STATE packet.

  - An error exists while processing malformed Tektronix .rf5 file.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.7.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:ver, test_version:"1.0.7")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.0.7");
  security_message(data:report);
  exit(0);
}

exit(99);