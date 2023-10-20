# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802735");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-06 16:59:20 +0530 (Fri, 06 Apr 2012)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2012-1796");

  script_name("IBM Db2 Tivoli Monitoring Agent Privilege Escalation Vulnerability (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48279/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52326");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21586193");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79970");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21588098");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to perform certain actions
  with escalated privileges and gain sensitive information.");

  script_tag(name:"affected", value:"IBM Db2 version 9.5 through FP8.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in Tivoli Monitoring Agent.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.5 FP9 or later.");

  script_tag(name:"summary", value:"IBM DB2 is prone to a privilege escalation vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
