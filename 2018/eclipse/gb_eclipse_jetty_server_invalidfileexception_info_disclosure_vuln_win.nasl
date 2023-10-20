# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108501");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-12536");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-14 16:15:00 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2018-07-05 12:17:02 +0530 (Thu, 05 Jul 2018)");
  script_name("Eclipse Jetty Server InvalidPathException Information Disclosure Vulnerability (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=535670");

  script_tag(name:"summary", value:"Eclipse Jetty Server is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of bad queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Eclipse Jetty Server versions 9.2.x, 9.3.x
  before 9.3.24.v20180605 and 9.4.x before 9.4.11.v20180605.");

  script_tag(name:"solution", value:"Upgrade to Eclipse Jetty Server version
  9.3.24.v20180605 or 9.4.11.v20180605 or later as per the series. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+", exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"9.2.0", test_version2:"9.3.24.20180604")) {
  fix = "9.3.24.v20180605";
}

else if(version_in_range(version:vers, test_version:"9.4.0", test_version2:"9.4.11.20180604")) {
  fix = "9.4.11.v20180605";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
