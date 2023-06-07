# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804243");
  script_version("2023-05-05T09:09:19+0000");
  script_cve_id("CVE-2014-1695");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2014-03-04 17:31:09 +0530 (Tue, 04 Mar 2014)");

  script_name("OTRS Email HTML Injection Vulnerability (OSA-2014-03)");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) is prone to a HTML injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in OTRS core system which fails to properly
  sanitize user-supplied input before using it in dynamically generated content.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"OTRS versions 3.1.x prior to 3.1.20, 3.2.x prior to 3.2.15 and
  3.3.x prior to 3.3.5.");

  script_tag(name:"solution", value:"Update to version 3.1.20, 3.2.15, 3.3.5 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65844");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-03-xss-issue");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.19") ||
   version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.14") ||
   version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.20/3.2.15/3.3.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
