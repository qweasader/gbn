# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151071");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2023-09-29 05:06:35 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 20:00:00 +0000 (Tue, 14 Nov 2023)");

  script_cve_id("CVE-2023-46728");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid DoS Vulnerability (GHSA-cg5h-v6vc-w33f, SQUID-2021:8)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability in
  the Gopher gateway.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to a NULL pointer dereference bug Squid is vulnerable to a
  Denial of Service attack against Squid's Gopher gateway.

  The gopher protocol is always available and enabled in Squid prior to Squid 6.0.1.

  Responses triggering this bug are possible to be received from any gopher server, even those
  without malicious intent.

  This flaw was part of the 'Squid Caching Proxy Security Audit: 55 vulnerabilities and 35 0days'
  publication in October 2023 and filed as 'Null Pointer Dereference in Gopher Response
  Handling'.");

  script_tag(name:"affected", value:"Squid version 2.x and later prior to version 6.0.1.");

  script_tag(name:"solution", value:"Update to version 6.0.1 or later.

  As a workaround reject all gopher URL requests. Please see the referenced vendor advisory for more
  information.

  Note: Removing the gopher port 70 from the Safe_ports ACL is not sufficient to avoid this
  vulnerability.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-cg5h-v6vc-w33f");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/");
  script_xref(name:"URL", value:"https://joshua.hu/squid-security-audit-35-0days-45-exploits");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/11/3");
  script_xref(name:"URL", value:"https://gist.github.com/rousskov/9af0d33d2a1f4b5b3b948b2da426e77d");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/gopher-nullpointer.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2", test_version_up: "6.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
