# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143164");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-11-22 03:26:51 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 21:21:00 +0000 (Tue, 10 Dec 2019)");

  script_cve_id("CVE-2019-18976");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2019-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If Asterisk receives a re-invite initiating T.38 faxing and has
  a port of 0 and no c line in the SDP, a crash will occur.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x and 13.21 Certified Asterisk.");

  script_tag(name:"solution", value:"Update to version 13.29.2, 13.21-cert5 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-008.html");

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
  if (version =~ "^13\.21cert") {
    if (revcomp(a: version, b: "13.21cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.29.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.29.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(99);
