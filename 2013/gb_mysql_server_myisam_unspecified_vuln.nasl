# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803499");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2012-0583");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-06-04 13:16:35 +0530 (Tue, 04 Jun 2013)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("MySQL Server Component MyISAM Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53061");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to affect
  availability via unknown vectors.");
  script_tag(name:"affected", value:"MySQL version 5.1.x before 5.1.61 and 5.5.x before 5.5.20");
  script_tag(name:"insight", value:"Unspecified error in MySQL Server component related to MyISAM.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"MySQL is prone to an unspecified vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^5\.[15]") {
  if(version_in_range(version:version, test_version:"5.1", test_version2:"5.1.60") ||
     version_in_range(version:version, test_version:"5.5", test_version2:"5.5.19")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"5.1.61/5.5.20");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
