###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Wicket Information Disclosure Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112076");
  script_version("2021-10-12T09:28:32+0000");

  script_cve_id("CVE-2014-0043");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-11 17:32:00 +0000 (Wed, 11 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-10 15:13:12 +0200 (Tue, 10 Oct 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Wicket Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Apache Wicket is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By issuing requests to special URLs handled by Wicket it is possible to
  check for the existence of particular classes in the classpath and thus
  check whether a third party library with a known security vulnerability is in use.");

  script_tag(name:"affected", value:"Apache Wicket versions 1.5.x before 1.5.11 and 6.x before
  6.14.0.");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket 1.5.11 or 6.14.0.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/d95e962f2f059a09f5abf7086c3f4ed22d2ae2c21499d0de95d4435d@1392986987@%3Cannounce.wicket.apache.org%3E");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)) {
  exit(0);
}

if(version_in_range(version:ver, test_version:"1.5", test_version2:"1.5.10")){
  fix = "1.5.11";
}
else if(ver =~ "^(6\.)")
{
  if(version_is_less(version:ver, test_version:"6.14.0")){
    fix = "6.14.0";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:ver, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
