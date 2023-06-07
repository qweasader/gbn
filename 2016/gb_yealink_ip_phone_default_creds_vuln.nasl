###############################################################################
# OpenVAS Vulnerability Test
#
# Yealink IP Phone Default Credentials
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

CPE = "cpe:/o:yealink:voip_phone_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106326");
  script_version("2020-08-11T09:37:56+0000");
  script_tag(name:"last_modification", value:"2020-08-11 09:37:56 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-10-05 08:36:01 +0700 (Wed, 05 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Yealink IP Phone Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_yealink_ip_phone_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("yealink_ipphone/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The Yealink IP Phone has default credentials set.");

  script_tag(name:"impact", value:"A remote attacker may gain sensitive information or reconfigure the Yealink
  IP Phone.");

  script_tag(name:"solution", value:"Change the password");

  script_tag(name:"vuldetect", value:"Try to login with the default credentials.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/servlet?p=login&q=login';
data = 'username=admin&pwd=admin&jumpto=status&acc=';

req = http_post_put_req(port: port, url: url, data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res !~ "HTTP/1\.. 401" && "Location: /servlet?p=status&q=load" >< res) {
  report = "It was possible to login with user 'admin' and password 'admin'.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
