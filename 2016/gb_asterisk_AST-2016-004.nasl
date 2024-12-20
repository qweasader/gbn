# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106174");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-08-09 08:53:51 +0700 (Tue, 09 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Long Contact URIs DoS Vulnerability (AST-2016-004)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk may crash when processing an incoming REGISTER request
  if that REGISTER contains a Contact header with a lengthy URI.

  This crash will only happen for requests that pass authentication. Unauthenticated REGISTER requests
  will not result in a crash occurring.

  This vulnerability only affects Asterisk when using PJSIP as its SIP stack. The chan_sip module does
  not have this problem.");

  script_tag(name:"impact", value:"An authenticated attacker may crash Asterisk causing a denial of
  service condition.");

  script_tag(name:"affected", value:"Asterisk Open Source version 13.x and Certified Asterisk
  version 13.1.");

  script_tag(name:"solution", value:"Update to version 13.8.1, 13.1-cert5 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-004.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "^13\.1cert") {
    if (revcomp(a: version, b: "13.1cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.1-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.3.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.3.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(0);
