##############################################################################
# OpenVAS Vulnerability Test
#
# HUMAX Gateway Backup File Download Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE_PREFIX = "cpe:/a:humaxdigital";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106917");
  script_version("2021-09-16T13:01:47+0000");
  script_cve_id("CVE-2017-7316", "CVE-2017-7317", "CVE-2017-7315");
  script_tag(name:"last_modification", value:"2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-07-03 11:22:04 +0700 (Mon, 03 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 18:05:00 +0000 (Fri, 07 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HUMAX Gateway Backup File Download Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_humax_gateway_detect.nasl");
  script_mandatory_keys("humax_gateway/detected");

  script_tag(name:"summary", value:"Humax HG100R devices are prone to a backup file download vulnerability.
  This file contains sensitive information which may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42284/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/view/basic/GatewaySettings.bin';

if (http_vuln_check(port: port, url: url, pattern: "Content-Type: application/x-download", check_header: TRUE,
                    extra_check: "Content-disposition: attachment; filename=GatewaySettings.bin")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
