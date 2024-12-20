# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106462");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-9938");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-09 14:10:48 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The chan_sip channel driver has a liberal definition for whitespace when
attempting to strip the content between a SIP header name and a colon character. Headers such as 'Contact\x01:'
will be seen as a valid Contact header.

This mostly does not pose a problem until Asterisk is placed in tandem with an authenticating SIP proxy. In such
a case, a crafty combination of valid and invalid To headers can cause a proxy to allow an INVITE request into
Asterisk without authentication since it believes the request is an in-dialog request. However, because of the
bug described above, the request will look like an out-of-dialog request to Asterisk. Asterisk will then process
the request as a new call. The result is that Asterisk can process calls from unvetted sources without any
authentication.

If you do not use a proxy for authentication, or if your proxy is dialog-aware, or if you use chan_pjsip instead
of chan_sip, then this issue does not affect you.");

  script_tag(name:"impact", value:"An authenticated remote attacker may make calls without any authentication.");

  script_tag(name:"affected", value:"Asterisk Open Source 11.x, 13.x, 14.x and Certified Asterisk 11.6 and
13.8.");

  script_tag(name:"solution", value:"Upgrade to Version 11.25.1, 13.13.1, 14.2.1, 11.6-cert16, 13.8-cert4 or
later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-009.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94789");

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
    if (revcomp(a: version, b: "11.6cert16") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert16");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.25.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.25.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.8cert") {
    if (revcomp(a: version, b: "13.8cert4") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.8-cert4");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.13.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
