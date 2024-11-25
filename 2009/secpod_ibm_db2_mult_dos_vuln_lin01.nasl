# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900678");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2009-1905", "CVE-2009-1906");

  script_name("IBM Db2 Multiple Vulnerabilities - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35171");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50909");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ38874");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker bypass security restrictions,
  cause a denial of service or gain elevated privileges.");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpak 17, 9.1 prior to Fixpak 7 and
  9.5 prior to Fixpak 4.");

  script_tag(name:"insight", value:"- An error in DRDA Services component can be exploited via an IPv6 address
  in the correlation token in the APPID string.

  - An unspecified error can be exploited to connect to Db2 databases without
    a valid password if ldap-based authentication is used and the LDAP server allows anonymous binds.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpak 17, 9.1 Fixpak 7, 9.5 Fixpak 4 or later.");

  script_tag(name:"summary", value:"IBM DB2 is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.17");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.6a")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.7");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.3b")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.0.4");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
