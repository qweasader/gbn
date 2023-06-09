###############################################################################
# OpenVAS Vulnerability Test
#
# Magento RSS Feed Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807532");
  script_version("2021-10-13T13:01:32+0000");
  script_cve_id("CVE-2016-2212");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-13 13:01:32 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:55 +0530 (Wed, 06 Apr 2016)");
  script_name("Magento RSS Feed Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Magento Web E-Commerce Platform is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unsafe way of
  comparing 'increment_id' and 'customer_id' parameters in the
  'getOrderByStatusUrlKey' method of the 'Mage_Rss_Helper_Order' class in
  the '/app/code/core/Mage/Rss/Helper/Order.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download order comments and other order-related information.");

  script_tag(name:"affected", value:"Magento CE 1.9.2.2 and prior versions.");

  script_tag(name:"solution", value:"Update to Magento CE 1.9.2.3 or later or
  apply the SUPEE-7405 patch bundle available at the references.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135941/KIS-2016-02.txt");
  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-7405");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.magentocommerce.com/products/downloads/magento");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!magVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_is_less_equal(version:magVer, test_version:"1.9.2.2"))
{
  report = report_fixed_ver(installed_version:magVer, fixed_version:"1.9.2.3");
  security_message(data:report, port:http_port);
  exit(0);
}

exit(99);
