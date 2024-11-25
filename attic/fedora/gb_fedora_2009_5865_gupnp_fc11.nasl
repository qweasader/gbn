# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64229");
  script_cve_id("CVE-2009-2174");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 11 FEDORA-2009-5865 (gupnp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"New upstream release that fixes a bug where the gupnp stack crashes when passed
empty content.

Other bugs fixed here.

  - bug#1570: gupnp doesn't set the pkgconfig lib dir correctly in 64 bit env.

  - bug#1574: Avoid using asserts.

  - bug#1592: gupnp_device_info_get_icon_url() does not return the closest match.

  - bug#1604: Crash on action without any content.

ChangeLog:

  * Wed Jun  3 2009 Peter Robinson  0.12.8-1

  - New upstream release");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gupnp' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5865");
  script_tag(name:"summary", value:"The remote host is missing an update to gupnp
announced via advisory FEDORA-2009-5865.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
