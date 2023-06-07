# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114129");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-09-03 15:29:48 +0200 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-1000071");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Roundcube Webmail <= 1.3.4 Insecure Permissions Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to an insecure permissions
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability allows remote attackers to exfiltrate a
  user's password protected secret GPG key file using a specially crafted URL. This affects the
  enigma plugin in Roundcube installations on nginx web servers with the default configuration set.
  The security of the enigma plugin's home folder relies on a .htaccess file, which will not be
  honored by nginx. Multiple 'easy install scripts' for Roundcube Webmail improperly configure
  permissions/nginx upon installation.");

  script_tag(name:"affected", value:"Roundcube Webmail versions 1.3.4 and earlier.");

  script_tag(name:"solution", value:"Enigma config: Move the home folder outside of the scope of
  the webserver.

  plugins/enigma/config.inc.php: $config['enigma_pgp_homedir'] = '/other/dir'

  Also you may manually configure nginx to restrict access to the default folder. Refer to the
  provided 'bitbucket' link.");

  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/commit/48417c5fc9f6eb4b90500c09596606d489c700b5");
  script_xref(name:"URL", value:"https://bitbucket.org/zhb/iredmail/issues/130/multiple-security-issues-with-default");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.3.4")) {
  report = report_fixed_ver(installed_version: version, extra: "Refer to the solution tag for mitigation measures.", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
