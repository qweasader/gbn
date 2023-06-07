# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900004");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_cve_id("CVE-2008-2463");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("Microsoft Access Snapshot Viewer ActiveX Control Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"affected", value:"MS Access Snapshot (with/without) MS Office Access (2000/2002/2003) - Windows (All).");
  script_tag(name:"summary", value:"Microsoft Access Snapshot in Microsoft Office Access is prone
 to ActiveX control vulnerabilities.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Overview: Microsoft Access Snapshot in Microsoft Office Access is prone
        to ActiveX control vulnerabilities.

        The ActiveX control for viewing a snapshot of Microsoft Access report.
        A specially crafted Web site, when visited can inject arbitrary code
        because of a vulnerability in the ActiveX control.");
  script_tag(name:"impact", value:"Exploitation involves convincing the victim to view an HTML
        document (eg., web page, HTML email, or email attachment). When a
        user views the web page, the vulnerability could allow remove code
        execution.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/837785");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30114");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2012");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/955179");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-041");
  exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                 "\Uninstall\Snapshot Viewer")){
    exit(0);
 }

 ocxFile = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
               item:"Install Path");
 ocxFile += "\snapview.ocx";

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ocxFile);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ocxFile);

 name   =  kb_smb_name();
 login  =  kb_smb_login();
 pass   =  kb_smb_password();
 domain =  kb_smb_domain();
 port   =  kb_smb_transport();

 soc = open_sock_tcp(port);
 if(!soc){
    exit(0);
 }

info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share);

if(isnull(info)) {
   close(soc);
   exit(0);
}

uid = info["uid"];
tid = info["tid"];

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid){
    exit(0);
 }

 fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 off = fsize - 90000;

 while(fsize != off)
 {
    data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
    data = str_replace(find:raw_string(0), replace:"", string:data);
    version = strstr(data, "ProductVersion");
    if(!version){
        off += 16383;
    }
    else break;
 }

 if(!version){
    exit(0);
 }

 v = "";
 for(i = strlen("ProductVersion"); i < strlen(version); i++)
 {
    if((ord(version[i]) < ord("0") ||
            ord(version[i]) > ord("9")) && version[i] != "."){
        break;
    }
    else
        v += version[i];
 }

 if(egrep(pattern:"^10\.0\.([0-4][0-9].*|5[0-4].*|55[0-2][0-9])", string:v)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
