# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00062.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45806");
  script_oid("1.3.6.1.4.1.25623.1.0.870919");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:37 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2010-4530");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0523-02");
  script_name("RedHat Update for ccid RHSA-2013:0523-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ccid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"ccid on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Chip/Smart Card Interface Devices (CCID) is a USB smart card reader
  standard followed by most modern smart card readers. The ccid package
  provides a Generic, USB-based CCID driver for readers, which follow this
  standard.

  An integer overflow, leading to an array index error, was found in the way
  the CCID driver processed a smart card's serial number. A local attacker
  could use this flaw to execute arbitrary code with the privileges of the
  user running the PC/SC Lite pcscd daemon (root, by default), by inserting a
  specially-crafted smart card. (CVE-2010-4530)

  This update also fixes the following bug:

  * Previously, CCID only recognized smart cards with 5V power supply. With
  this update, CCID also supports smart cards with different power supply.
  (BZ#808115)

  All users of ccid are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ccid", rpm:"ccid~1.3.9~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ccid-debuginfo", rpm:"ccid-debuginfo~1.3.9~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
