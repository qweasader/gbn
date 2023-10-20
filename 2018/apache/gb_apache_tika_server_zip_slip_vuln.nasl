# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814055");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-11762");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 21:02:00 +0000 (Tue, 20 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-09-27 15:38:59 +0530 (Thu, 27 Sep 2018)");
  script_name("Apache Tika Server Zip Slip Arbitrary File Overwrite Vulnerability");

  script_tag(name:"summary", value:"Apache Tika Server is prone to a zip slip arbitrary file
  overwrite vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where a user does not specify an
  extract directory on the commandline and the input file has an embedded file with an absolute
  path, tika-app overwrites that file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to overwrite
  arbitrary files.");

  script_tag(name:"affected", value:"Apache Tika Server from versions 0.9 through 1.18.");

  script_tag(name:"solution", value:"Update to version 1.19 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/ab2e1af38975f5fc462ba89b517971ef892ec3d06bee12ea2258895b@%3Cdev.tika.apache.org%3E");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"0.9", test_version2:"1.18")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.19", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);