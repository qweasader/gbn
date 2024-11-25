# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804801");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164",
                "CVE-2014-5165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-08-07 09:40:53 +0530 (Thu, 07 Aug 2014)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities-01 (Aug 2014) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'dissect_log' function in plugins/irda/packet-irda.c within the
ASN.1 BER dissector.

  - An error in 'read_new_line' function in wiretap/catapult_dct2000.c within the
Catapult DCT2000 dissector.

  - An error in 'APN decode' functionality in epan/dissectors/packet-gtp.c and
epan/dissectors/packet-gsm_a_gm.c within the GTP and GSM Management dissectors.

  - An error in 'rlc_decode_li' function in epan/dissectors/packet-rlc.c within
the RLC dissector.

  - An error in 'dissect_ber_constrained_bitstring' function in
epan/dissectors/packet-ber.c within the ASN.1 BER dissector.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a DoS (Denial of
Service).");
  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.9 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.9 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69005");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-08.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-11.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.10)")
{
  if(version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.8"))
  {
    report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.10.0 - 1.10.8");
    security_message(port:0, data:report);
    exit(0);
  }
}
