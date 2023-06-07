###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Spark Cluster Arbitrary Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805066");
  script_version("2021-10-21T13:57:32+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-04-22 12:59:34 +0530 (Wed, 22 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Spark Cluster Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"Apache Spark Cluster is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read the secured data or not.");

  script_tag(name:"insight", value:"Apache Spark contains a flaw that is
  triggered when submitting a specially crafted job to an unsecured
  cluster.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Spark Cluster versions 0.0.x, 1.1.x, 1.2.x, 1.3.x");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36562");
  script_xref(name:"URL", value:"http://codebreach.in/blog/2015/03/arbitary-code-execution-in-unsecured-apache-spark-cluster");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7777);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

http_port = http_get_port(default:7777);

if(http_vuln_check(port:http_port, url:"/", check_header:TRUE,
   pattern:">Memory:<", extra_check: make_list(">Drivers:<",
   'Spark Master at spark')))
{
  security_message(http_port);
  exit(0);
}
