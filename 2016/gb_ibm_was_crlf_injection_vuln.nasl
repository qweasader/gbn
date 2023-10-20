# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807853");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0359");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-05 11:50:52 +0530 (Tue, 05 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server CRLF Injection Vulnerability");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to a CRLF injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified error
  within application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct HTTP response splitting attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.43, 8.0 before 8.0.0.13, and 8.5 before 8.5.5.10, 8.5 Liberty
  before Liberty Fix 16.0.0.2");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) to 7.0.0.43 or 8.0.0.13 or 8.5.5.10 or Liberty Fix 16.0.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21982526");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

liberty = get_kb_item("ibm_websphere_application_server/liberty/profile/installed");

if (liberty)
{
  if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.9"))
  {
    fix = "16.0.0.2";
    VULN = TRUE;
  }
} else
{
  if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.41"))
  {
    fix = "7.0.0.43";
    VULN = TRUE;
  }

  else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.12"))
  {
    fix = "8.0.0.13";
    VULN = TRUE;
  }

  else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.5.9"))
  {
   fix = "8.5.5.10";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
