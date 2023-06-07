###############################################################################
# OpenVAS Vulnerability Test
#
# Asterisk SDP Offer DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106461");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-9937");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-12-09 14:10:48 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk SDP Offer DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a SDP offer denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an SDP offer or answer is received with the Opus codec and with the
  format parameters separated using a space the code responsible for parsing will recursively call itself until
  it crashes. This occurs as the code does not properly handle spaces separating the parameters. This does NOT
  require the endpoint to have Opus configured in Asterisk. This also does not require the endpoint to be
  authenticated. If guest is enabled for chan_sip or anonymous in chan_pjsip an SDP offer or answer is still
  processed and the crash occurs.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.12.0 and higher and 14.x.");

  script_tag(name:"solution", value:"Upgrade to Version 13.13.1, 14.2.1 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-008.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94792");

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
  if ( version_in_range(version: version, test_version: "13.12.0", test_version2: "13.13.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.13.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
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
