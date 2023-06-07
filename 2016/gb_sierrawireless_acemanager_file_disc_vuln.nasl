###############################################################################
# OpenVAS Vulnerability Test
#
# Sierra Wireless AceManager File Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/h:sierra_wireless:acemanager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106076");
  script_version("2021-10-13T14:01:34+0000");
  script_tag(name:"last_modification", value:"2021-10-13 14:01:34 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-05-17 09:27:34 +0700 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-17 17:42:00 +0000 (Thu, 17 Jun 2021)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-6479");

  script_name("Sierra Wireless AceManager File Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sierrawireless_acemanager_detect.nasl");
  script_mandatory_keys("sierra_wireless_acemanager/installed");

  script_tag(name:"summary", value:"Sierra Wireless AceManager is prone to a file disclosure
vulnerability");

  script_tag(name:"vuldetect", value:"Checks if the file filteredlogs.txt is accessible.");

  script_tag(name:"insight", value:"The file filteredlogs.txt is available without authorization. No
sensitive information is written to the accessible log file, although because of the diagnostic nature of
such files an attacker may be able to learn operational characteristics of the device, e.g., the sequence of
operations at boot time. The accessible log file only persists until the next log view operation or until
the device reboots.");

  script_tag(name:"impact", value:"An attacker may be able to learn operational characteristics of the
gateway, e.g., the sequence of operations at boot time.");

  script_tag(name:"affected", value:"ALEOS 4.4.2 and earlier.");

  script_tag(name:"solution", value:"Upgrade to version 4.4.4 or later");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-105-01");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url =  "/filteredlogs.txt";
req = http_get(item: url, port: port);
res = http_keepalive_send_recv(port: port, data: req);

if ("ALEOS_EVENTS_" >< res || "ALEOS_WAN_" >< res) {
  report = http_report_vuln_url(port: port, url:url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
