# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807043");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-0479");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Unspecified Vulnerability -03 Jan16");

  script_tag(name:"summary", value:"Oracle Database Server is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  error in the XDK and XDB - XML Database component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.3, 11.2.0.4, and 12.1.0.1");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74084");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dbPort = get_app_port(cpe:CPE)) exit(0);
if(!dbVer = get_app_version(cpe:CPE, port:dbPort)) exit(0);

if(version_is_equal(version:dbVer, test_version:"12.1.0.1") ||
   version_is_equal(version:dbVer, test_version:"11.2.0.3") ||
   version_is_equal(version:dbVer, test_version:"11.2.0.4")) {
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}

exit(99);
