###############################################################################
# OpenVAS Vulnerability Test
#
# CRE Loaded Multiple Security Bypass Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802104");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2009-5076", "CVE-2009-5077");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CRE Loaded Multiple Security Bypass Vulnerabilities");
  script_xref(name:"URL", value:"http://hosting-4-creloaded.com/node/116");
  script_xref(name:"URL", value:"https://www.creloaded.com/fdm_file_detail.php?file_id=191");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass authentication and
  gain administrator privileges.");

  script_tag(name:"affected", value:"CRE Loaded version before 6.4.0");

  script_tag(name:"insight", value:"The flaws are due to

  - An error when handling 'PHP_SELF' variable, by includes/application_top.php
    and admin/includes/application_top.php.

  - Request, with 'login.php' or 'password_forgotten.php' appended as the
    'PATH_INFO', which bypasses a check that uses 'PHP_SELF', which is not
    properly handled by includes/application_top.php and
    admin/includes/application_top.php.");

  script_tag(name:"solution", value:"Upgrade to CRE Loaded version 6.4.0 or later");

  script_tag(name:"summary", value:"CRE Loaded is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.creloaded.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list_unique("/cre", "/cre-loaded", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('<title>CRE Loaded' >< res)
  {
    ver = eregmatch(pattern:"v([0-9.]+)" , string:res);
    if (ver != NULL)
    {
      if(version_is_less(version:ver, test_version:"6.4.0")){
        report = report_fixed_ver(installed_version:ver, fixed_version:"6.4.0");
        security_message(port: port, data: report);
      }
    }
  }
}

exit(99);
