# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140343");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-09-01 12:19:52 +0700 (Fri, 01 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-14099", "CVE-2017-14100");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Vulnerabilities (Aug 2017)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk is prone to multiple vulnerabilities:

  - Unauthorized data disclosure (AST-2017-005)

  - Unauthorized command execution (AST-2017-006)");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may inject shell commands or
  hijack the media stream.");

  script_tag(name:"affected", value:"Asterisk Open Source 11.x, 13.x, 14.x and Certified Asterisk
  11.6 and 13.13.");

  script_tag(name:"solution", value:"Update to version 11.25.2, 13.17.1, 14.6.1, 11.6-cert17,
  13.13-cert5 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-005.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-006.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^11\.") {
  if (version =~ "^11\.6cert") {
    if (revcomp(a: version, b: "11.6cert17") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert17");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.25.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.25.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.13cert") {
    if (revcomp(a: version, b: "13.13cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.17.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.17.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.6.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.6.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);