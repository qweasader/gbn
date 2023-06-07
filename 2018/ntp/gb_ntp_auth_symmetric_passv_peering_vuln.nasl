###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Authenticated Symmetric Passive Peering Remote Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812793");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-7170");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 14:01:00 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2018-03-07 12:17:55 +0530 (Wed, 07 Mar 2018)");
  script_name("NTP.org 'ntpd' Authenticated Symmetric Passive Peering Remote Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3454");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103194");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to a remote security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to if a system is
  set up to use a trustedkey and if one is not using the feature introduced in
  ntp-4.2.8p6 allowing an optional 4th field in the ntp.keys file to specify
  which IPs can serve time.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform some unauthorized
  actions to the application. This may aid in further attacks.");

  script_tag(name:"affected", value:"NTP.org's ntpd version 4.2.x before 4.2.8p7 and 4.3.x before 4.3.92.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p7 or 4.2.8p11
  or 4.3.92.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(version =~ "^4\.2") {
  if(revcomp(a:version, b:"4.2.8p7") < 0) {
    fix = "4.2.8p7 or 4.2.8p11";
  }
}
else if(version =~ "^4\.3") {
  if(revcomp(a:version, b:"4.3.92") < 0) {
    fix = "4.3.92 or 4.2.8p11";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);
