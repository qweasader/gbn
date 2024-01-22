# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809340");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-3042", "CVE-2016-0378");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:06:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-03 13:28:39 +0530 (Mon, 03 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Application Server 'Openid' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"IBM Websphere application server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An improper sanitization of input to vectors involving
    'OpenID' Connect clients.

  - An improper handling of exceptions when a default error page does not exist.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  authenticated users to inject arbitrary web script.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS)
  Liberty before 16.0.0.3");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Application
  Server (WAS) Liberty Fix 16.0.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21986716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93143");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed", "ibm_websphere_application_server/liberty/profile/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:wasVer, test_version:"16.0.0.3"))
{
  report = report_fixed_ver(installed_version:wasVer, fixed_version:"16.0.0.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
