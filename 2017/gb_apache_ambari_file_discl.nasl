###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Ambari Sensitive Data Exposure
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108161");
  script_version("2021-10-12T13:28:05+0000");
  script_tag(name:"last_modification", value:"2021-10-12 13:28:05 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2017-05-16 07:42:44 +0200 (Tue, 16 May 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-23 03:00:00 +0000 (Tue, 23 May 2017)");
  script_cve_id("CVE-2017-5655");
  script_name("Apache Ambari 2.2.2 - 2.4.2 / 2.5.0 Sensitive Data Exposure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.4.3");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-FixedinAmbari2.5.1");

  script_tag(name:"summary", value:"Apache Ambari might expose sensitive data to system users.");

  script_tag(name:"impact", value:"Sensitive data may be stored on disk in temporary files on the
  Ambari Server host. The temporary files are readable by any user authenticated on the host which
  might cause an exposure of sensitive data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Ambari 2.2.2 through 2.4.2 and 2.5.0.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.3/2.5.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"2.2.2", test_version2:"2.4.2" ) ||
    version_is_equal( version:vers, test_version:"2.5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.3/2.5.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );