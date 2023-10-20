# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126028");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-10 10:05:24 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-07 15:13:00 +0000 (Tue, 07 Mar 2023)");

  script_cve_id("CVE-2023-1070");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamPass < 3.0.0.22 Arbitrary File Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_mandatory_keys("teampass/detected");

  script_tag(name:"summary", value:"TeamPass is prone to an arbitrary file deletion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The file sources/export.queries.php can be exploited by any
  authenticated user to remove arbitrary txt files.");

  script_tag(name:"affected", value:"TeamPass prior to version 3.0.0.22.");

  script_tag(name:"solution", value:"Update to version 3.0.0.22 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/318bfdc4-7782-4979-956f-9ba2cc44889c/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "3.0.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0.22", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
