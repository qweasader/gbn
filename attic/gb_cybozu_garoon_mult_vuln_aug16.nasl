###############################################################################
# OpenVAS Vulnerability Test
#
# Cybozu Garoon Multiple Vulnerabilities - Aug16
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.1071655555");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-05-11 11:54:29 +0200 (Thu, 11 May 2017)");
  script_cve_id("CVE-2016-1213", "CVE-2016-1214", "CVE-2016-1215", "CVE-2016-1216", "CVE-2016-1217",
                "CVE-2016-1218", "CVE-2016-1219", "CVE-2016-1220");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 16:09:00 +0000 (Tue, 25 Apr 2017)");
  script_name("Cybozu Garoon Multiple Vulnerabilities (Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92601");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to multiple vulnerabilities.

  NOTE: This VT has been replaced by 'Cybozu Garoon Multiple Vulnerabilities - Aug16' (OID: 1.3.6.1.4.1.25623.1.0.107165) due to an erroneous OID.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to do redirection, XSS, authentication bypass, SQL injection and denial-of-services attacks.");

  script_tag(name:"affected", value:"Cybozu Garoon before version 4.2.2.");

  script_tag(name:"solution", value:"Update to Cybozu Garoon 4.2.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);