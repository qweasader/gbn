# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813536");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-12418");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-06-20 16:32:04 +0530 (Wed, 20 Jun 2018)");

  script_name("Apache Tika Server < 1.19 Junrar Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Apache Tika Server is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an infinite loop when
  handling corrupt RAR files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform denial of service.");

  script_tag(name:"affected", value:"Apache Tika Server versions through latest release 1.18");

  script_tag(name:"solution", value:"Update to version 1.19 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://github.com/junrar/junrar/commit/ad8d0ba8e155630da8a1215cee3f253e0af45817");
  script_xref(name:"URL", value:"https://tika.apache.org/1.19/index.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");
  script_require_ports("Services/www", 9998, 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:tPort, exit_no_version:TRUE)) exit(0);
tVer = infos['version'];
tPath = infos['location'];

if(version_is_less_equal(version:tVer, test_version:"1.18"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"1.19", install_path:tPath);
  security_message(data:report, port:tPort);
  exit(0);
}
exit(0);
