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
  script_oid("1.3.6.1.4.1.25623.1.0.800219");
  script_version("2021-05-10T08:29:54+0000");
  script_tag(name:"last_modification", value:"2021-05-10 08:29:54 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Tencent FoxMail Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Tencent FoxMail.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

CPE = "cpe:/a:tencent:foxmail:";

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");
include("misc_func.inc");

foreach keypart( make_list_unique( "Foxmail_is1", "Foxmail", registry_enum_keys( key: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ),
  registry_enum_keys( key: "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ) ) ) {

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
  if( ! registry_key_exists( key: key ) ) {
    key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
    if( ! registry_key_exists( key: key ) ) continue;
  }

  name = registry_get_sz( key: key, item: "DisplayName" );
  if( "Foxmail" >!< name ) continue;
  set_kb_item( name: "foxmail/detected", value: TRUE );

  version = "unknown";

  loc = registry_get_sz( key: key, item: "UninstallString" );
  if( ! isnull( loc ) ){
    loc = ereg_replace( pattern: "(uninst(all)?\.exe)", string: loc, replace: "", icase: TRUE );

    file_path = loc + "Foxmail.exe";
    escaped_file_path = ereg_replace( pattern: "\\", string: file_path, replace: "\\" );

    host    = get_host_ip();
    usrname = kb_smb_login();
    passwd  = kb_smb_password();

    if( host && usrname && passwd && ! wmi_file_is_file_search_disabled() ) {

      domain = kb_smb_domain();
      if( domain ) usrname = domain + '\\' + usrname;

      handle = wmi_connect( host: host, username: usrname, password: passwd );
      if( handle ) {
        versList = wmi_file_fileversion( handle: handle, filePath: escaped_file_path, includeHeader: FALSE );
        if( versList && is_array( versList ) ) {
          foreach vers( keys( versList ) ) {
            if( versList[vers] && version = eregmatch( string: versList[vers], pattern: "([0-9.]+)" ) ) {
              version = vers;
              set_kb_item( name: "Foxmail/Win/Ver", value: version );
              break;
            }
          }
        }
        wmi_close( wmi_handle: handle );
      }
    }
  }

  register_and_report_cpe( app: "Tencent Foxmail",
                           ver: version,
                           concluded: name,
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: loc );
  break;
}

exit( 0 );
