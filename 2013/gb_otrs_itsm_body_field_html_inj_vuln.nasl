# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803937");
  script_version("2023-07-14T16:09:26+0000");
  script_cve_id("CVE-2012-2582");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-25 19:02:06 +0530 (Wed, 25 Sep 2013)");
  script_name("OTRS ITSM 'Body' Field HTML Injection Vulnerability (OSA-2012-01)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML via an e-mail message body.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize user-supplied
  input before using it.");

  script_tag(name:"solution", value:"Upgrade to OTRS (Open Ticket Request System) version 2.4.13, 3.0.15 and 3.1.9
  or later, and OTRS::ITSM version 3.1.6, 3.0.6 and 2.1.5 or apply the patch from the referenced vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"OTRS (Open Ticket Request System) or OTRS:ITSM is prone to HTML injection vulnerability.");

  script_tag(name:"affected", value:"OTRS (Open Ticket Request System) version 2.4.x up to and including 2.4.12,
  3.0.x up to and including 3.0.14 and 3.1.x up to and including 3.1.8

  OTRS::ITSM 3.1.0 up to and including 3.1.5, 3.0.0 up to and including 3.0.5
  and 2.1.0 up to and including 2.1.4");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54890");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20359/");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2012-01-en/");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:otrs:otrs", "cpe:/a:otrs:otrs_itsm");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if("cpe:/a:otrs:otrs_itsm" >< cpe) {
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.5") ||
     version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.5") ||
     version_in_range(version:vers, test_version:"2.1.0", test_version2:"2.1.4")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

else if("cpe:/a:otrs:otrs" >< cpe) {
  if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.12") ||
     version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.14") ||
     version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.8")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
