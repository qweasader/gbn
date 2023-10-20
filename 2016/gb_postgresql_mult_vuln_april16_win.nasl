# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807913");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3065", "CVE-2016-2193");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 22:09:00 +0000 (Thu, 14 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-04-26 17:11:55 +0530 (Tue, 26 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Multiple Vulnerabilities - Apr16 (Windows)");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the 'brin_page_type' and 'brin_metapage_info' functions in
    the pageinspect extension.

  - PostgreSQL does not properly maintain row-security status in cached
    plans.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass intended access restrictions, to obtain sensitive
  server memory information and to cause denial of service.");

  script_tag(name:"affected", value:"PostgreSQL version 9.5.x before
  9.5.2.");

  script_tag(name:"solution", value:"Upgrade to version 9.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-9-5-2.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1656/");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(version_in_range(version:vers, test_version:"9.5.0", test_version2:"9.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.5.2", install_path:loc);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
