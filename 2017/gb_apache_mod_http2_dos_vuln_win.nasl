# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811238");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2017-9789");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-07-17 16:42:23 +0530 (Mon, 17 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server 'mod_http2' Denial-Of-Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in read after
  free error in 'mod_http2.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.26.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.4.27 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jul/33");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99568");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/143361");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "2.4.26") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.27", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
