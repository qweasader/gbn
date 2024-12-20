# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_portal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810734");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2014-8912");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-04-07 17:26:57 +0530 (Fri, 07 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM WebSphere Portal Sensitive Information Disclosure Vulnerability (swg21963226)");

  script_tag(name:"summary", value:"IBM Websphere Portal is prone to sensitive information Disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to failure to restrict access
  to resources located within web applications. An attacker could exploit this
  vulnerability to obtain configuration data and other sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to obtain view configuration data and other potentially sensitive
  information on the target system.");

  script_tag(name:"affected", value:"IBM WebSphere Portal versions 6.1.0 before 6.1.0.6 CF27,
  IBM WebSphere Portal versions 6.1.5 before 6.1.5.3 CF27,
  IBM WebSphere Portal versions 7.0.0 before 7.0.0.2 CF29,
  IBM WebSphere Portal versions 8.0.0 before 8.0.0.1 CF19, and
  IBM WebSphere Portal versions 8.5.0 before CF08.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Portal
  Fix Pack 6.1.0.6 with Cumulative Fix 27 (CF27).Fix Pack 6.1.5.3 with
  Cumulative Fix 27 (CF27), Upgrade to Fix Pack 7.0.0.2 with Cumulative
  Fix 30 (CF30), Upgrade to Fix Pack 8.0.0.1 with Cumulative Fix 19 (CF18),
  8.5.0 Cumulative Fix 08 (CF08) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PI47714");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033988");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963226");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24023835");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_portal_detect.nasl");
  script_mandatory_keys("ibm_websphere_portal/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
 exit(0);
}

if(webVer =~ "^8\.5\.0")
{
  if(version_is_less(version:webVer, test_version:"8.5.0.0.08"))
  {
    fix = "8.5.0.0 CF08";
    VULN = TRUE;
  }
}

else if(webVer =~ "^8\.0\.0")
{
  if(version_is_less(version:webVer, test_version:"8.0.0.1.19"))
  {
    fix = "8.0.0.1 CF19";
    VULN = TRUE;
  }
}

else if(webVer =~ "^7\.0\.0")
{
  if(version_is_less(version:webVer, test_version:"7.0.0.2.30"))
  {
    fix = "7.0.0.2 CF30";
    VULN = TRUE;
  }
}

else if(webVer =~ "^6\.1\.5")
{
  if(version_is_less(version:webVer, test_version:"6.1.5.3.27"))
  {
    fix = "6.1.5.3 CF27";
    VULN = TRUE;
  }
}

else if(webVer =~ "^6\.1\.0")
{
  if(version_is_less(version:webVer, test_version:"6.1.0.6.27"))
  {
    fix = "6.1.0.6 CF27";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:webVer, fixed_version:fix);
  security_message(data:report, port:webPort);
  exit(0);
}
