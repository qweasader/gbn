# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806042");
  script_version("2024-10-29T05:05:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Dell SonicWall NetExtender Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Dell SonicWall NetExtender on Windows.

  The script logs in via smb, searches for 'Dell SonicWall NetExtender' in the
  registry and gets the version from 'DisplayVersion' string from
  registry.

  This VT has been replaced by the VT 'SonicWall NetExtender Detection (Windows SMB Login)'
  (OID: 1.3.6.1.4.1.25623.1.0.170894).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);