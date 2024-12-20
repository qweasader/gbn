# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871693");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-04 05:41:58 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-0764");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-01 14:13:00 +0000 (Wed, 01 Jul 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for NetworkManager RHSA-2016:2581-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'NetworkManager'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"NetworkManager is a system network service
that manages network devices and connections, attempting to keep active network
connectivity when available. Its capabilities include managing Ethernet, wireless,
mobile broadband (WWAN), and PPPoE devices, as well as providing VPN integration
with a variety of different VPN services.

The following packages have been upgraded to a newer upstream version:
NetworkManager (1.4.0), NetworkManager-libreswan (1.2.4),
network-manager-applet (1.4.0), libnl3 (3.2.28). (BZ#1264552, BZ#1296058,
BZ#1032717, BZ#1271581)

Security Fix(es):

  * A race condition vulnerability was discovered in NetworkManager.
Temporary files were created insecurely when saving or updating connection
settings, which could allow local users to read connection secrets such as
VPN passwords or WiFi keys. (CVE-2016-0764)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"NetworkManager on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2581-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00017.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-debuginfo", rpm:"NetworkManager-debuginfo~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.2.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-debuginfo", rpm:"NetworkManager-libreswan-debuginfo~1.2.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.2.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.4.0~12.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3", rpm:"libnl3~3.2.28~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3-cli", rpm:"libnl3-cli~3.2.28~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnl3-debuginfo", rpm:"libnl3-debuginfo~3.2.28~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnma", rpm:"libnma~1.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"network-manager-applet-debuginfo", rpm:"network-manager-applet-debuginfo~1.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.4.0~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
