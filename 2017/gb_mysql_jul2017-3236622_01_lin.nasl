# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811431");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-3650", "CVE-2017-3637", "CVE-2017-3639", "CVE-2017-3638",
                "CVE-2017-3642", "CVE-2017-3643", "CVE-2017-3640", "CVE-2017-3644",
                "CVE-2017-3645", "CVE-2017-3529");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 11:04:19 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Mysql Security Updates (jul2017-3236622) 01 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A flaw in the C API component to partially access data.

  - A flaw in the X Plugin component.

  - A flaw in the Server: DML component.

  - A flaw in the Server: Optimizer component.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.18 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99779");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99775");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99746");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(version_in_range(version:mysqlVer, test_version:"5.7.0", test_version2:"5.7.18"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch");
  security_message(data:report, port:sqlPort);
  exit(0);
}
