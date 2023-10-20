# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-February/016521.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880580");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0108");
  script_cve_id("CVE-2009-4144", "CVE-2009-4145");
  script_name("CentOS Update for NetworkManager CESA-2010:0108 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"NetworkManager on CentOS 5");
  script_tag(name:"insight", value:"NetworkManager is a network link manager that attempts to keep a wired or
  wireless network connection active at all times.

  A missing network certificate verification flaw was found in
  NetworkManager. If a user created a WPA Enterprise or 802.1x wireless
  network connection that was verified using a Certificate Authority (CA)
  certificate, and then later removed that CA certificate file,
  NetworkManager failed to verify the identity of the network on the
  following connection attempts. In these situations, a malicious wireless
  network spoofing the original network could trick a user into disclosing
  authentication credentials or communicating over an untrusted network.
  (CVE-2009-4144)

  An information disclosure flaw was found in NetworkManager's
  nm-connection-editor D-Bus interface. If a user edited network connection
  options using nm-connection-editor, a summary of those changes was
  broadcasted over the D-Bus message bus, possibly disclosing sensitive
  information (such as wireless network authentication credentials) to other
  local users. (CVE-2009-4145)

  Users of NetworkManager should upgrade to these updated packages, which
  contain backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~0.7.0~9.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~0.7.0~9.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~0.7.0~9.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~0.7.0~9.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-gnome", rpm:"NetworkManager-gnome~0.7.0~9.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
