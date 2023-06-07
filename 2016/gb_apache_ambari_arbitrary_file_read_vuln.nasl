###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Ambari Arbitrary File Read Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808649");
  script_version("2021-10-08T11:02:44+0000");
  script_cve_id("CVE-2016-0731");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-08 11:02:44 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-18 21:34:00 +0000 (Wed, 18 May 2016)");
  script_tag(name:"creation_date", value:"2016-08-09 18:48:58 +0530 (Tue, 09 Aug 2016)");
  script_name("Apache Ambari < 2.2.1 Arbitrary File Read Vulnerability");

  script_tag(name:"summary", value:"Apache Ambari is prone to an arbitrary file read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in file browser view in the WebHDFS
  URL configuration.");

  script_tag(name:"impact", value:"Successfully exploitation will allows remote authenticated
  administrators to read arbitrary files.");

  script_tag(name:"affected", value:"Apache Ambari versions 1.7 through 2.2.0.");

  script_tag(name:"solution", value:"Update to version 2.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"2.2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.2.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);