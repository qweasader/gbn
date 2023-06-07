# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803938");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2012-4600");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2013-09-25 19:21:59 +0530 (Wed, 25 Sep 2013)");

  script_name("OTRS Email Message XSS Vulnerability (OSA-2012-02)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize
  user-supplied input before using it.");

  script_tag(name:"solution", value:"Update to version 2.4.14, 3.0.16, 3.1.10 or later.");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"OTRS versions 2.4.x prior to 2.4.14, 3.0.x prior to 3.0.16 and
  3.1.x prior to 3.1.10.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51031/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50465/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55328");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79451");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20959/");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2012-02-en/");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.13") ||
   version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.15") ||
   version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.14/3.0.16/3.1.10");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
