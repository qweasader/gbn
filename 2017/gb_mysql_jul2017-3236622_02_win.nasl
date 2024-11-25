# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811432");
  script_version("2024-02-29T14:37:57+0000");
  script_cve_id("CVE-2017-3651", "CVE-2017-3653", "CVE-2017-3652", "CVE-2017-3635",
                "CVE-2017-3648", "CVE-2017-3641");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-29 14:37:57 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-19 11:04:26 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Mysql Security Updates (jul2017-3236622) 02 - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A flaw in the Client mysqldump component.

  - A flaw in the Server: DDL component.

  - A flaw in the C API component.

  - A flaw in the Connector/C component.

  - A flaw in the Server: Charsets component.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to have an impact on confidentiality, integrity and
  availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.56 and earlier,
  5.6.36 and earlier, 5.7.18 and earlier, on Windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99730");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99767");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.5.0", test_version2:"5.5.56") ||
   version_in_range(version:version, test_version:"5.6.0", test_version2:"5.6.36") ||
   version_in_range(version:version, test_version:"5.7.0", test_version2:"5.7.18")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
