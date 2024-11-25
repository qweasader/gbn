# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809049");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178",
                "CVE-2016-7179", "CVE-2016-7180");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-30 15:08:00 +0000 (Fri, 30 Sep 2016)");
  script_tag(name:"creation_date", value:"2016-09-15 12:37:30 +0530 (Thu, 15 Sep 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Sep 2016) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The 'epan/dissectors/packet-ipmi-trace.c' script in the IPMI trace dissector
    mishandles string.

  - A stack-based buffer overflow error in 'epan/dissectors/packet-catapult-dct2000.c'
    script in the Catapult DCT2000 dissector.

  - The 'epan/dissectors/packet-umts_fp.c' script in the UMTS FP dissector
    does not ensure that memory is allocated for certain data structures.

  - The 'epan/dissectors/packet-catapult-dct2000.c' script in the Catapult
    DCT2000 dissector does not restrict the number of channels.

  - The 'epan/dissectors/packet-h225.c' in the H.225 dissector calls snprintf
    with one of its input buffers as the output buffer.

  - The 'epan/dissectors/packet-qnet6.c' in the QNX6 QNET dissector mishandles
    MAC address data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.6
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.6 or
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-55.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92889");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-54.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-53.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-51.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"2.0", test_version2:"2.0.5"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.0.6");
  security_message(port:0, data:report);
  exit(0);
}
