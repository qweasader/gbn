###############################################################################
# OpenVAS Vulnerability Test
#
# Winamp Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801659");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-2586", "CVE-2010-4370", "CVE-2010-4371",
                "CVE-2010-4372", "CVE-2010-4373", "CVE-2010-4374");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Winamp Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42004");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?t=324322");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?threadid=159785");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"insight", value:"- Multiple integer overflow errors in in_nsv.dll in the in_nsv plugin allow
    remote attackers to execute arbitrary code via a crafted Table of Contents.

  - Multiple integer overflow errors in the in_midi plugin allow remote
    attackers to cause buffer overflow.

  - A buffer overflow error in the in_mod plugin allows remote attackers to
    have an unspecified impact via vectors related to the comment box.

  - An error in_mkv plugin  allows remote attackers to cause a denial of service
    via a Matroska Video file containing a string with a crafted length.

  - An error in in_mp4 plugin allows remote attackers to cause a denial of
    service via crafted metadata or albumart in an invalid MP4 file.");
  script_tag(name:"solution", value:"upgrade to Winamp 5.6 or later.");
  script_tag(name:"summary", value:"Winamp is prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"Winamp versions prior to 5.6");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less(version:winampVer, test_version:"5.6")){
  report = report_fixed_ver(installed_version:winampVer, fixed_version:"5.6");
  security_message(port: 0, data: report);
}
