# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809288");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-6500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-09-23 14:25:39 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Information Exposure Vulnerability (Sep 2016) - Windows");

  script_tag(name:"summary", value:"ownCloud is prone to Information Exposure Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an incorrect usage
  of an ownCloud internal file system function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to list directory contents and possibly cause a denial of
  service.");

  script_tag(name:"affected", value:"ownCloud Server before 8.0.6 and 8.1.x
  before 8.1.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 8.0.6 or
  8.1.1 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-014");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76689");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^8") {

  if(version_is_less(version:version, test_version:"8.0.6")) {
    fix = "8.0.6";
    VULN = TRUE;
  }

  else if(version_is_equal(version:version, test_version:"8.1.0")) {
    fix = "8.1.1";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
