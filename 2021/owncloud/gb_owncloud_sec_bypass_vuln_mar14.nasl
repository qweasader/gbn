# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117648");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-09-08 08:55:44 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-2044");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 5.0 RCE Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ownCloud is prone to an remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Incomplete blacklist vulnerability in ajax/upload.php in
  ownCloud, when running on Windows, allows remote authenticated users to bypass intended access
  restrictions, upload files with arbitrary names, and execute arbitrary code via an Alternate Data
  Stream (ADS) syntax in the filename parameter, as demonstrated using .htaccess::$DATA to upload a
  PHP program.");

  script_tag(name:"affected", value:"ownCloud prior to version 5.0 and running on a Windows host.");

  script_tag(name:"solution", value:"Update to version 5.0 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210325025334/https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-2044/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125585/ownCloud-4.0.x-4.5.x-Remote-Code-Execution.html");

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

if (version_is_less(version: version, test_version: "5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
