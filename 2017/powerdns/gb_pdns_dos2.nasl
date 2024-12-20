# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140594");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-12 09:39:48 +0700 (Tue, 12 Dec 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-15120");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in the parsing of authoritative answers in PowerDNS
  Recursor, leading to a NULL pointer dereference when parsing a specially crafted answer containing a CNAME of a
  different class than IN.");

  script_tag(name:"affected", value:"PowerDNS Recursor from 4.0.0 up to and including 4.0.7.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.8 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-08.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.8");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
