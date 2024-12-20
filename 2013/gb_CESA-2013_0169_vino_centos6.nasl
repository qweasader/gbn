# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019206.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881579");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-24 09:27:31 +0530 (Thu, 24 Jan 2013)");
  script_cve_id("CVE-2011-0904", "CVE-2011-0905", "CVE-2011-1164", "CVE-2011-1165",
                "CVE-2012-4429");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2013:0169");
  script_name("CentOS Update for vino CESA-2013:0169 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vino'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"vino on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Vino is a Virtual Network Computing (VNC) server for GNOME. It allows
  remote users to connect to a running GNOME session using VNC.

  It was found that Vino transmitted all clipboard activity on the system
  running Vino to all clients connected to port 5900, even those who had not
  authenticated. A remote attacker who is able to access port 5900 on a
  system running Vino could use this flaw to read clipboard data without
  authenticating. (CVE-2012-4429)

  Two out-of-bounds memory read flaws were found in the way Vino processed
  client framebuffer requests in certain encodings. An authenticated client
  could use these flaws to send a specially-crafted request to Vino, causing
  it to crash. (CVE-2011-0904, CVE-2011-0905)

  In certain circumstances, the vino-preferences dialog box incorrectly
  indicated that Vino was only accessible from the local network. This could
  confuse a user into believing connections from external networks are not
  allowed (even when they are allowed). With this update, vino-preferences no
  longer displays connectivity and reachable information. (CVE-2011-1164)

  There was no warning that Universal Plug and Play (UPnP) was used to open
  ports on a user's network router when the 'Configure network automatically
  to accept connections' option was enabled (it is disabled by default) in
  the Vino preferences. This update changes the option's description to avoid
  the risk of a UPnP router configuration change without the user's consent.
  (CVE-2011-1165)

  All Vino users should upgrade to this updated package, which contains
  backported patches to resolve these issues. The GNOME session must be
  restarted (log out, then log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"vino", rpm:"vino~2.28.1~8.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
