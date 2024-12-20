# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150852");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-08-14 03:22:11 +0000 (Mon, 14 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 17:38:00 +0000 (Fri, 18 Aug 2023)");

  script_cve_id("CVE-2023-39418");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 15.x < 15.4 MERGE Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to a vulnerability in the MERGE command.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PostgreSQL 15 introduced the MERGE command, which fails to test
  new rows against row security policies defined for UPDATE and SELECT. If UPDATE and SELECT
  policies forbid some row that INSERT policies do not forbid, a user could store such rows.
  Subsequent consequences are application-dependent. This affects only databases that have used
  CREATE POLICY to define a row security policy.");

  script_tag(name:"affected", value:"PostgreSQL version 15.x prior to 15.4.");

  script_tag(name:"solution", value:"Update to version 15.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-154-149-1312-1216-1121-and-postgresql-16-beta-3-released-2689/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2023-39418/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "15.0", test_version_up: "15.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
