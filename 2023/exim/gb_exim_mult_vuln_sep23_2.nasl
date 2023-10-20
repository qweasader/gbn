# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151090");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. To avoid wrong stats about CVE coverage the "creation_date" of the original VT
  # has been kept here because all CVEs had been covered at this time.
  script_tag(name:"creation_date", value:"2023-09-29 04:31:53 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-42117", "CVE-2023-42119");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim < 4.96.2 Multiple Vulnerabilities (Sep 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_detect.nasl");
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-42117: Improper neutralization of special elements remote code execution (RCE)

  - CVE-2023-42119: dnsdb out-of-bounds read information disclosure");

  script_tag(name:"affected", value:"Exim version 4.96.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.96.2 or later.");

  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2023-zdi.txt");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1471/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1473/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.96.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.96.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
