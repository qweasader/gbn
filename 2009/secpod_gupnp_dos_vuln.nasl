# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900682");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2174");
  script_name("GUPnP Message Handling Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35390");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1597");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_gupnp_detect.nasl");
  script_mandatory_keys("GUPnP/Ver");
  script_tag(name:"impact", value:"Successful exploitation via specially crafted messages will allow attackers to
  run arbitrary code, crash the application and cause cause denial of service.");
  script_tag(name:"affected", value:"GUPnP Version 0.12.7 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error when processing subscription or control
  messages with an empty content.");
  script_tag(name:"solution", value:"Upgrade to version 0.12.8 or later.");
  script_tag(name:"summary", value:"GUPnP is prone to denial of service (DoS)
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

gupnpVer = get_kb_item("GUPnP/Ver");
if(!gupnpVer)
  exit(0);

if(version_is_less(version:gupnpVer, test_version:"0.12.8")){
  report = report_fixed_ver(installed_version:gupnpVer, fixed_version:"0.12.8");
  security_message(port: 0, data: report);
}
