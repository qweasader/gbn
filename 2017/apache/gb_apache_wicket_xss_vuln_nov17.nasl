# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812102");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2012-5636");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-18 16:08:00 +0000 (Sat, 18 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-11-10 16:11:14 +0530 (Fri, 10 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket Cross-Site Scripting Vulnerability (Nov 2017)");

  script_tag(name:"summary", value:"Apache Wicket is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to JavaScript statements
  can break out of a '<script>' tag in the rendered response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Wicket 1.4.x before 1.4.22,
  1.5.x before 1.5.10, and 6.x before 6.4.0");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket version 1.4.22 or
  1.5.10 or 6.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://wicket.apache.org/news/2013/03/03/cve-2012-5636.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101644");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wkPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:wkPort, exit_no_version:TRUE)) exit(0);
wkVer = infos['version'];
wkpath = infos['location'];

if(version_in_range(version:wkVer, test_version:"1.4", test_version2:"1.4.21")){
  fix = "1.4.22";
}

else if(version_in_range(version:wkVer, test_version:"1.5", test_version2:"1.5.9")){
  fix = "1.5.10";
}

else if(wkVer =~ "^(6\.)")
{
  if(version_is_less(version:wkVer, test_version:"6.4.0")){
    fix = "6.4.0";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:wkVer, fixed_version:fix, install_path:wkpath);
  security_message(data:report, port:wkPort);
  exit(0);
}
exit(0);
