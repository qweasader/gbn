# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:powerdns:recursor';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140543");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-11-28 08:39:40 +0700 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-15090", "CVE-2017-15092", "CVE-2017-15094");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PowerDNS Recursor is prone to multiple vulnerabilities:

  - Insufficient validation of DNSSEC signatures (CVE-2017-15090)

  - Cross-Site Scripting in the web interface (CVE-2017-15092)

  - Memory leak in DNSSEC parsing (CVE-2017-15094)");

  script_tag(name:"affected", value:"PowerDNS Recursor from 4.0.0 up to and including 4.0.6.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.7 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-03.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-05.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-07.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
