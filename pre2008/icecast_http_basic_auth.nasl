# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:icecast:icecast';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15397");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10311");
  script_xref(name:"OSVDB", value:"6075");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ICECast HTTP basic authorization DoS");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_icecast_detect.nasl");
  script_mandatory_keys("icecast/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 2.0.1 or later.");

  script_tag(name:"summary", value:"The remote server runs ICECast 2.0.0, an open source streaming audio server.

This version is affected by a remote denial of service.

An remote attacker could send specially crafted URL, with a long string passed in an Authorization header that
will result in a loss of availability for the service.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
