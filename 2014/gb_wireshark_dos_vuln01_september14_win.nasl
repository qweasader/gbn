# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804909");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2014-6430", "CVE-2014-6428", "CVE-2014-6427", "CVE-2014-6432",
                "CVE-2014-6431", "CVE-2014-6429", "CVE-2014-6423", "CVE-2014-6424");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-09-23 15:24:29 +0530 (Tue, 23 Sep 2014)");

  script_name("Wireshark DOS Vulnerability-01 (Sep 2014) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - SnifferDecompress function does not prevent data overwrites, validate
    bitmask data, and does not properly handle empty input data.

  - Improper initialization of certain ID value in the dissect_spdu function
    under SES dissector.

  - Off-by-one error in the is_rtsp_request_or_reply function under the RTSP
    dissector.

  - The dissect_v9_v10_pdu_data function under Netflow dissector refers incorrect
    offset and start variables.

  - An error in tvb_raw_text_add function in MEGACO dissector");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to cause denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x
  before 1.10.10 and 1.12.x before 1.12.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 1.12.1, 1.10.10 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61590");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69865");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if((version_in_range(version:version, test_version:"1.10.0", test_version2:"1.10.9")) ||
  (version_is_equal(version:version, test_version:"1.12.0")))
{
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

