# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106239");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-12 12:33:46 +0700 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 00:39:00 +0000 (Tue, 25 Apr 2017)");

  script_cve_id("CVE-2016-7551");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk RTP Resource Exhaustion Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a RTP resource exhaustion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The overlap dialing feature in chan_sip allows chan_sip to report to
a device that the number that has been dialed is incomplete and more digits are required. If this functionality
is used with a device that has performed username/password authentication RTP resources are leaked. This
occurs because the code fails to release the old RTP resources before allocating new ones in this scenario.
If all resources are used then RTP port exhaustion will occur and no RTP sessions are able to be set up.");

  script_tag(name:"impact", value:"An authenticated remote attacker may cause a partial denial of service
condition.");

  script_tag(name:"affected", value:"Asterisk Open Source 11.x, 13.x and Certified Asterisk 11.6 and 13.8.");

  script_tag(name:"solution", value:"Upgrade to Version 11.23.1, 13.11.1, 11.6-cert15, 13.8-cert3 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-007.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92888");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^11\.") {
  if (version =~ "^11\.6cert") {
    if (revcomp(a: version, b: "11.6cert15") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert15");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.23.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.23.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.8cert") {
    if (revcomp(a: version, b: "13.8cert3") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.8-cert3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.11.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.11.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(0);
