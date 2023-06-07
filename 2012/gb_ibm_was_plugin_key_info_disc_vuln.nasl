###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere Application Server 'plugin-key.kdb' Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802851");
  script_version("2022-02-15T13:40:32+0000");
  script_cve_id("CVE-2012-2162");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-15 13:40:32 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-05-11 17:31:58 +0530 (Fri, 11 May 2012)");
  script_name("IBM WebSphere Application Server 'plugin-key.kdb' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74900");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591172");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21588312");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain sensitive
  information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) 8.0 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Plug-in, which uses unencrypted
  HTTP communication after expiration of the plugin-key.kdb password. Which
  allows remote attackers to sniff the network, or spoof arbitrary server
  and further perform a man-in-the-middle (MITM) attacks to obtain sensitive information.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.0")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);