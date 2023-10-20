# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802413");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-1362");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-18 18:06:52 +0530 (Wed, 18 Jan 2012)");
  script_name("IBM WebSphere Application Server IVT Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46736");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site scripting
  attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.41

  IBM WebSphere Application Server (WAS) version 7.0 before 7.0.0.19.");

  script_tag(name:"insight", value:"The flaw is due to an error in Installation Verification Test (IVT)
  application in the Install component, which allows remote attackers to inject
  arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.0.41 or 7.0.0.19 or later.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.40")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.41");
  security_message(port:0, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.18")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.0.19");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);