# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146371");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-07-23 09:43:58 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-06 19:45:00 +0000 (Fri, 06 Aug 2021)");

  script_cve_id("CVE-2021-32558", "CVE-2021-32686");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple DoS Vulnerabilities (AST-2021-008, AST-2021-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32558: If the IAX2 channel driver receives a packet that contains an unsupported media
  format it can cause a crash to occur in Asterisk.

  - CVE-2021-32686: Depending on the timing, it's possible for Asterisk to crash when using a TLS
  connection if the underlying socket parent/listener gets destroyed during the handshake.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 16.x, 17.x, 18.x and 16.x Certified
  Asterisk.");

  script_tag(name:"solution", value:"Update to version 13.38.3, 16.19.1, 17.9.4, 18.5.1, 16.8-cert10
  or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-008.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-009.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version_is_less(version: version, test_version: "13.38.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.38.3");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^16\.") {
  if (version =~ "^16\.[0-9]+cert") {
    if (revcomp(a: version, b: "16.8cert10") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert10");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.19.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.19.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "17.0", test_version2: "17.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.9.4");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "18.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.5.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
