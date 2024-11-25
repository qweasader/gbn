# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811841");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2014-7808");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:12 +0530 (Wed, 04 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket 'CryptoMapper' CSRF Vulnerability");

  script_tag(name:"summary", value:"Apache Wicket is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Wicket's default security
  settings of the usage of CryptoMapper to encrypt/obfuscate pages urls, which is not
  strong enough. It is possible to predict the encrypted version of an url based on
  the previous history.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to defeat a cryptographic protection mechanism and predict encrypted URLs by
  leveraging use of CryptoMapper as the default encryption provider.");

  script_tag(name:"affected", value:"Apache Wicket versions before 1.5.13, 6.x before
  6.19.0, and 7.x before 7.0.0-M5.");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket 1.5.13 or 6.19.0
  or 7.0.0-M5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.smrrd.de/cve-2014-7808-apache-wicket-csrf-2014.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100946");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"1.5.13")){
  fix = "1.5.13";
}

else if(version =~ "^6\.") {
  if(version_is_less(version:version, test_version:"6.19.0")) {
    fix = "6.19.0";
  }
}

else if(version =~ "^7\." && revcomp(a:version, b:"7.0.0.M5") < 0) {
  fix = "7.0.0-M5";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
