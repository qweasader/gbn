# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114017");
  script_version("2021-09-29T05:25:13+0000");
  script_tag(name:"last_modification", value:"2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2018-08-06 13:40:12 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_name("Portainer UI No Authentication Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("global_settings.nasl", "gb_portainer_detect.nasl");
  script_mandatory_keys("portainer/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf");

  script_tag(name:"summary", value:"The script checks if the Portainer Dashboard UI has no
  authentication enabled at the remote web server.");

  script_tag(name:"insight", value:"The installation of Portainer might be misconfigured and
  therefore unprotected and exposed to the public.");

  script_tag(name:"vuldetect", value:"Check if authentication is enabled.

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"Access to the dashboard gives you top level access to all aspects
  of administration for the cluster it is assigned to manage. That includes managing applications,
  containers, starting workloads, adding and modifying applications, and setting key security
  controls.");

  script_tag(name:"solution", value:"It is highly recommended to enable authentication and create an
  administrator user to avoid exposing your dashboard with administrator privileges to the public.
  Always choose a secure password, especially if your dashboard is exposed to the public.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("network_func.inc");
include("host_details.inc");

CPE = "cpe:/a:portainer:portainer";

if(!is_public_addr())
  exit(0);

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

res = http_get_cache(port: port, item: "/api/status");
if(!res)
  exit(0);

if(egrep(pattern: '\\"Authentication\\"\\s*:\\s*false', string: res)) {
  report = "Authentication in Portainer Dashboard UI is disabled!";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);