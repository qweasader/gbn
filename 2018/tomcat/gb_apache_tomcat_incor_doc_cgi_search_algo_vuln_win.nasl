# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812694");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2017-15706");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 16:31:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-02-06 11:43:37 +0530 (Tue, 06 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat Incorrectly Documented CGI Search Algorithm - Windows");

  script_tag(name:"summary", value:"Apache Tomcat has an incorrectly documented CGI search algorithm.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the description of the
  search algorithm used by the CGI Servlet to identify which script to execute
  was not correct.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will result
  some scripts failing to execute as expected and other scripts to execute
  unexpectedly.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M22 to 9.0.1
  Apache Tomcat versions 8.5.16 to 8.5.23
  Apache Tomcat versions 8.0.45 to 8.0.47
  Apache Tomcat versions 7.0.79 to 7.0.82 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.2,
  8.5.24, 8.0.48, 7.0.84 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/e1ef853fc0079cdb55befbd2dac042934e49288b476d5f6a649e5da2@<announce.tomcat.apache.org>");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos['version'];
path = infos['location'];

if(appVer =~ "^8\.5")
{
  if(version_in_range(version:appVer, test_version: "8.5.16", test_version2: "8.5.23")){
    fix = "8.5.24";
  }
} else if(appVer =~ "^7\.0")
{
  if(version_in_range(version:appVer, test_version: "7.0.79", test_version2: "7.0.82")){
    fix = "7.0.84";
  }
} else if(appVer =~ "^8\.0")
{
  if(version_in_range(version:appVer, test_version: "8.0.45", test_version2: "8.0.47")){
    fix = "8.0.48";
  }
} else if(appVer =~ "^9\.0")
{
  if((revcomp(a:appVer, b: "9.0.0.M22") >= 0) && (revcomp(a:appVer, b: "9.0.2") < 0)){
    fix = "9.0.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(port:tomPort, data: report);
  exit(0);
}
exit(0);
