# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812850");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2018-1302");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-02 16:48:45 +0530 (Mon, 02 Apr 2018)");
  script_name("Apache HTTP Server Denial of Service Vulnerability (Apr 2018) - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the Apache HTTP Server
  writes a NULL pointer potentially to an already freed memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to destroy an HTTP/2 stream, resulting in a denial of service condition.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.4.17, 2.4.18,
  2.4.20, 2.4.23 and from 2.4.25 to 2.4.29.");

  script_tag(name:"solution", value:"Update to version 2.4.30 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2018/03/24/8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103528");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2018/03/24/2");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

affected = make_list("2.4.17", "2.4.18", "2.4.20", "2.4.23", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29");

if(version_in_range(version:vers, test_version:"2.4.17", test_version2:"2.4.29")) {
  foreach version(affected) {
    if(vers == version) {
      report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.30", install_path:path);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
