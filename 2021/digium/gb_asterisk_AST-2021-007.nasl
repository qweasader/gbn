# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146370");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-07-23 09:36:42 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-07 02:05:00 +0000 (Sat, 07 Aug 2021)");

  script_cve_id("CVE-2021-31878");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2021-007)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability in
  the PJSIP channel driver.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Asterisk receives a re-INVITE without SDP after having sent
  a BYE request a crash will occur. This occurs due to the Asterisk channel no longer being present
  while code assumes it is.");

  script_tag(name:"affected", value:"Asterisk Open Source 16.17.0, 16.18.0, 16.19.0, 18.3.0, 18.4.0
  and 18.5.0.");

  script_tag(name:"solution", value:"Update to version 16.19.1, 18.5.1 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-007.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "16.17.0", test_version2: "16.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.19.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "18.3.0", test_version2: "18.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.5.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
