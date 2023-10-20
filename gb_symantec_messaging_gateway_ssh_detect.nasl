# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105719");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-17 12:36:46 +0200 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Get Symantec Messaging Gateway Version via SSH.");

  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Service detection");
  script_tag(name:"summary", value:"Get Symantec Messaging Gateway Version via SSH.");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/restricted_shell");
  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );


ret = ssh_cmd( socket:sock, cmd:"update notes", return_errors:TRUE, nosh:TRUE );
if( "Symantec Messaging Gateway" >!< ret )
{
  close( sock );
  exit( 0 );
}

vers = "unknown";
set_kb_item( name:"symantec_smg/detected", value:TRUE );
set_kb_item( name:"symantec_smg/ssh/detected", value:TRUE );

ret = ssh_cmd( socket:sock, cmd:"show -v", return_errors:TRUE, nosh:TRUE );
if( "Version:" >< ret )
{
  lines = split( ret, keep:FALSE );
  foreach line ( lines )
  {
    if( line =~ "^Version:" ) continue;
    if( line =~ "^[0-9.-]+" )
    {
      version = eregmatch( pattern:"^([0-9.-]+)", string:line );
      if( ! isnull( version[1] ) )
      {
        vers = version[1];
        if( "-" >< vers )
        {
          _v = split( vers, sep:"-", keep:FALSE );
          vers = _v[0];
          patch = _v[1];
        }
      }
    }
    # Since version 10.6.3 the patch version is shown in the patch installation history e.g.
    # SMG patch installation history:
    #      patch-10.6.3-266    2017-06-29 20:35
    if (line =~ "patch-") {
      p = eregmatch(pattern: "patch-[0-9.]+-([0-9]+)", string: line);
      if (!isnull(p[1])) {
        patch = p[1];
        break;
      }
    }
  }
}

if( vers )
  set_kb_item( name:"symantec_smg/ssh/version", value:vers );

if( patch )
  set_kb_item( name:"symantec_smg/ssh/patch", value:patch );

exit(0);
