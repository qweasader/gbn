###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere Application Server WS-Security XML Encryption Weakness Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801888");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-1209");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("IBM WebSphere Application Server WS-Security XML Encryption Weakness Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67115");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47831");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1084");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24029632");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21474220");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to obtain plaintext data
  from a JAX-RPC or JAX-WS Web Services.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 6.1 before 6.1.0.39 and
  7.0 before 7.0.0.17.");

  script_tag(name:"insight", value:"The flaw is caused by a weak encryption algorithm being used by WS-Security
  to encrypt data exchanged via a Web Service (JAX-WS or JAX-RPC), which could
  allow attackers to decrypt the encrypted data contained in web requests.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"For WebSphere Application Server 6.1:

  Apply the latest Fix Pack (6.1.0.39 or later) or APAR PM34841.

  For WebSphere Application Server 7.0:

  Apply the latest Fix Pack (7.0.0.17 or later) or APAR PM34841.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:ibm:websphere_application_server";

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.1", test_version2:"6.1.0.37") ||
   version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.0.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.0.38/7.0.0.16");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);