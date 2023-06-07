###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress 'json' User Enumeration Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.809892");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2017-5487");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-03-03 17:16:53 +0530 (Fri, 03 Mar 2017)");
  script_name("WordPress 'json' User Enumeration Vulnerability");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95391");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8715");

  script_tag(name:"summary", value:"WordPress is prone to a user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  the response.");

  script_tag(name:"insight", value:"The flaw exists due to
  'wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php' in the
  REST API implementation in WordPress 4.7 before 4.7.1 does not properly
  restrict listings of post authorsimproper access restriction to some
  sensitive pages.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to obtain sensitive information.");

  script_tag(name:"affected", value:"WordPress versions 4.7 and earlier.");

  script_tag(name:"solution", value:"Update to WordPress version 4.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  # This NVT produces to much false positive....
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
