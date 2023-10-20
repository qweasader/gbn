# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805931");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-4757");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-21 11:38:02 +0530 (Tue, 21 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Unspecified Vulnerability-04 Jul15");

  script_tag(name:"summary", value:"Oracle MySQL is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified error exists in the MySQL Server
  component via unknown vectors related to Server : Optimizer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to cause denial of service attack.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.42 and earlier,
  and 5.6.23 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75759");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.[56]\.")
{
  if(version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.23") ||
     version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.42"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}
