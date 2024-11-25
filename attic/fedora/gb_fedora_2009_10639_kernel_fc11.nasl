# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66133");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3612", "CVE-2009-2909", "CVE-2009-2908", "CVE-2009-2903", "CVE-2009-3290", "CVE-2009-2847", "CVE-2009-2910");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-10639 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update to kernel 2.6.30.9

Also fixes:

  - Kernel stack randomization bug

  - NULL dereference in r128 driver

  - ftrace memory corruption on module unload

  - boot hanging on some systems

  - some latency problems caused by scheduler bugs");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10639");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-10639.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=524124");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=528868");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=522331");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=527534");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=528887");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526788");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
