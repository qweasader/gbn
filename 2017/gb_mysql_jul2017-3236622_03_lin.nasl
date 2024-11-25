# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811435");
  script_version("2024-02-29T14:37:57+0000");
  script_cve_id("CVE-2017-3636");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 19:59:00 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-07-19 11:05:54 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Mysql Security Updates (jul2017-3236622) 03 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a flaw in the
  Client programs component.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to partially access data, partially modify data,
  and partially deny service.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.56 and earlier,
  5.6.36 and earlier, on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99736");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.5.0", test_version2:"5.5.56") ||
   version_in_range(version:version, test_version:"5.6.0", test_version2:"5.6.36")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
