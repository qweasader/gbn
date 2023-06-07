# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148036");
  script_version("2023-05-10T09:37:12+0000");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"creation_date", value:"2022-05-03 07:53:04 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 13:10:00 +0000 (Fri, 06 May 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-24706");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 3.2.2 Privilege Escalation Vulnerability - Windows - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can access an improperly secured default
  installation without authenticating and gain admin privileges. The CouchDB documentation has
  always made recommendations for properly securing an installation, including recommending using a
  firewall in front of all CouchDB installations.");

  script_tag(name:"affected", value:"Apache CouchDB version 3.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/w24wo0h8nlctfps65txvk0oc5hdcnv00");

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

if (version_is_less(version: version, test_version: "3.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
