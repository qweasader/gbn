###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Local Buffer Overflow And Sybil Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.813448");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2016-1549", "CVE-2018-7182", "CVE-2018-7170", "CVE-2018-7184", "CVE-2018-7185",
                "CVE-2018-7183", "CVE-2018-12327");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-06-25 17:21:15 +0530 (Mon, 25 Jun 2018)");
  script_name("NTP.org 'ntpd' < 4.2.8p12 / 4.3.x < 4.3.94 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/9b58ed8e0354e8deee50b0eebd1c011f");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/88200");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44909");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3505");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3012P12");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of input argument for an IPv4 or IPv6
  command-line parameter.

  - If a system is set up to use a trustedkey and if one is not using the feature
  allowing an optional 4th field in the ntp.keys file to specify which IPs can serve time.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute code or escalate to higher privileges and bypass certain security
  restrictions and perform some unauthorized actions to the application.
  This may aid in further attacks.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions 4.x up to, but not including 4.2.8p12,
  and 4.3.0 up to, but not including 4.3.94.");

  script_tag(name:"solution", value:"Update to version 4.2.8p12, 4.3.94 or later.");

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

if(version =~ "^4\.") {
  if(revcomp(a:version, b:"4.2.8p11") <= 0) {
    fix = "4.2.8p12";
  }
  else if(version =~ "^4\.3" && (revcomp(a:version, b:"4.3.94") < 0)) {
    fix = "4.3.94";
  }

  if(fix) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, proto:proto, data:report);
    exit(0);
  }
}

exit(99);