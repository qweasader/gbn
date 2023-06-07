###############################################################################
# OpenVAS Vulnerability Test
#
# JV2 Folder Gallery 'lang_file' Parameter Remote File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801351");
  script_version("2022-05-02T09:35:37+0000");
  script_cve_id("CVE-2010-2127");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("JV2 Folder Gallery 'lang_file' Parameter RFI Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jv2_folder_gallery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("jv2_folder_gallery/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40339");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12688");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/jv2foldergallery-rfi.txt");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary PHP code via a URL in the lang_file parameter.");

  script_tag(name:"affected", value:"JV2 Folder Gallery version 3.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input
  in 'lang_file' parameter in 'gallery/gallery.php' while including external files for processing.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"JV2 Folder Gallery is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

vers = get_kb_item("www/" + port + "/JV2/Folder/Gallery");
if(!vers)
  exit(0);

vers = eregmatch(pattern:"^(.+) under (/.*)$", string:vers);
if(!isnull(vers[1])) {
  if(version_is_less_equal(version:vers[1], test_version:"3.1")) {
    report = report_fixed_ver(installed_version:vers[1], fixed_version:"None");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
