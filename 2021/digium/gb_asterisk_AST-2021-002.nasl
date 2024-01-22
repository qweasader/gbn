# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145417");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-02-19 03:52:32 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 17:34:00 +0000 (Wed, 24 Feb 2021)");

  script_cve_id("CVE-2021-26717");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2021-002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability when
  negotiating T.38.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When re-negotiating for T.38 if the initial remote response was
  delayed just enough Asterisk would send both audio and T.38 in the SDP. If this happened, and the
  remote responded with a declined T.38 stream then Asterisk would crash.");

  script_tag(name:"affected", value:"Asterisk Open Source versions 16.15.0 through 16.16.0, 17.9.0
  through 17.9.1, 18.1.0 through 18.2.0 and Certified Asterisk versions 16.8-cert4 and 16.8-cert5.");

  script_tag(name:"solution", value:"Update to version 16.16.1, 17.9.2, 18.2.1, 16.8-cert6 or
  later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-002.html");

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
  if (version =~ "^16\.8cert") {
    if (revcomp(a: version, b: "16.8cert4") >= 0 && revcomp(a: version, b: "16.8cert6") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert6");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_in_range(version: version, test_version: "16.15.0", test_version2: "16.16.0")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.16.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "17.9.0", test_version2: "17.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.9.2");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "18.1.0", test_version2: "18.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.2.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
