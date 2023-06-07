###############################################################################
# OpenVAS Vulnerability Test
#
# Yahoo!Messenger is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2006 Xue Yong Zhi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11432");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6121");
  script_cve_id("CVE-2002-0320", "CVE-2002-0321", "CVE-2002-0031", "CVE-2002-0032", "CVE-2002-0322");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Yahoo!Messenger is installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Xue Yong Zhi");
  script_family("Windows");

  script_tag(name:"solution", value:"Uninstall this software.");

  script_tag(name:"summary", value:"Yahoo!Messenger - an instant messaging software, which may not be suitable
  for a business environment - is installed on the remote host. If its use
  is not compatible with your corporate policy, you should de-install it.

  This VT has been replaced by 'Yahoo! Messenger Version Detection' (OID: 1.3.6.1.4.1.25623.1.0.801149).");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
