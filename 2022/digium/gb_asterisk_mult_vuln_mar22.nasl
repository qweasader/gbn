# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147760");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-08 02:05:15 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-03 23:20:00 +0000 (Mon, 03 Jan 2022)");

  script_cve_id("CVE-2021-37706", "CVE-2022-21723", "CVE-2022-23608");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Vulnerabilities (AST-2022-004, AST-2022-005, AST-2022-006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-37706: Remote code execution (RCE) due to an integer underflow on STUN messages

  - CVE-2022-21723: Denial of service (DoS) due to an undefined behavior after freeing a dialog set

  - CVE-2022-23608: Out of bounds memory access in an unconstrained malformed multipart SIP
  message");

  script_tag(name:"affected", value:"Asterisk Open Source 16.x, 18.x, 19.x and 16.x Certified
  Asterisk.");

  script_tag(name:"solution", value:"Update to version 16.24.1, 18.10.1, 19.2.1, 16.8-cert13 or
  later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-004.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-005.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-006.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^16\.") {
  if (version =~ "^16\.[0-9]cert") {
    if (revcomp(a: version, b: "16.8cert13") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert13");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.24.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.24.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "18.10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.10.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "19.0", test_version2: "19.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.2.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
