# Copyright (C) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902138");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4719");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Discloser 'more' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/505478/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_discloser_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("discloser/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary SQL
  commands in the affected application.");

  script_tag(name:"affected", value:"Discloser version 0.0.4 rc2.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in the 'index.php'
  script when processing the 'more' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Discloser is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

discport = http_get_port(default:80);

discver = get_kb_item("www/" + discport + "/Discloser");
if(isnull(discver))
  exit(0);

discver = eregmatch(pattern:"^(.+) under (/.*)$", string:discver);
if(!isnull(discver[1]))
{
  # Discloser version 0.0.4 rc2
   if(version_is_equal(version:discver[1], test_version:"0.0.4.rc2")){
    security_message(discport);
  }
}
