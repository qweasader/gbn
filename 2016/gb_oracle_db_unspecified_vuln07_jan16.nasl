# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807047");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-4755", "CVE-2016-3488", "CVE-2016-5572", "CVE-2016-5497",
                "CVE-2016-5516", "CVE-2017-3240", "CVE-2017-3567", "CVE-2017-10120");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Unspecified Vulnerability - 07 Jan16");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified errors.

  - An unspecified error related to component 'RDBMS Security'.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server version
  12.1.0.2");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75882");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95477");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99867");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixDB");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dbVer = get_app_version(cpe:CPE, port:dbPort)){
  exit(0);
}

if(version_is_equal(version:dbVer, test_version:"12.1.0.2"))
{
  report = report_fixed_ver(installed_version:dbVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:dbPort);
  exit(0);
}

exit(99);
