# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104449");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-12-02 13:33:50 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-07 17:27:00 +0000 (Wed, 07 Dec 2022)");

  script_cve_id("CVE-2022-37325", "CVE-2022-42705", "CVE-2022-42706");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Vulnerabilities (AST-2022-007, AST-2022-008, AST-2022-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-37325: Remote Crash Vulnerability in H323 channel add on due to an exploitable stack
  buffer underflow

  - CVE-2022-42705: Denial of service (DoS) due to an use after free in res_pjsip_pubsub.c

  - CVE-2022-42706: Escalation of privileges because the GetConfig AMI Action can read files outside
  of Asterisk directory");

  script_tag(name:"affected", value:"Asterisk Open Source 16.x, 18.x, 19.x, 20.x and 18.x Certified
  Asterisk.");

  script_tag(name:"solution", value:"Update to version 16.29.1, 18.9-cert3, 18.15.1, 19.7.1, 20.0.1
  or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-007.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-008.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2022-009.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^18\.") {
  if (version =~ "^18\.[0-9]cert") {
    if (revcomp(a: version, b: "18.9-cert3") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "18.9-cert3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "18.15.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "18.15.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.29.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.29.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "19.0", test_version_up: "19.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.7.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_is_equal(version: version, test_version: "20.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
