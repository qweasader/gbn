# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809284");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2015-7699");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-09-23 12:35:00 +0530 (Fri, 23 Sep 2016)");
  script_name("ownCloud Remote Code Execution Vulnerability Sep16 (Windows)");

  script_tag(name:"summary", value:"ownCloud is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper check
  of the mount point options provided by a user via the web front end in the
  'files_external' app.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to instantiate arbitrary classes and possibly execute
  arbitrary code.");

  script_tag(name:"affected", value:"ownCloud Server before 7.0.9, 8.0.x
  before 8.0.7, and 8.1.x before 8.1.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 7.0.9 or 8.0.7
  or 8.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77329");

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

if(version =~ "^[87]") {

  if(version_is_less(version:version, test_version:"7.0.9")) {
    fix = "7.0.9";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.0.0", test_version2:"8.0.6")) {
    fix = "8.0.7";
    VULN = TRUE;
  }

  else if(version_in_range(version:version, test_version:"8.1.0", test_version2:"8.1.1")) {
    fix = "8.1.2";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
