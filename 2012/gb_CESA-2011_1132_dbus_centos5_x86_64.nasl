# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017795.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881446");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:53:00 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2200");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:1132");
  script_name("CentOS Update for dbus CESA-2011:1132 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"dbus on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  A denial of service flaw was found in the way the D-Bus library handled
  endianness conversion when receiving messages. A local user could use this
  flaw to send a specially-crafted message to dbus-daemon or to a service
  using the bus, such as Avahi or NetworkManager, possibly causing the
  daemon to exit or the service to disconnect from the bus. (CVE-2011-2200)

  All users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. For the update to take effect, all
  running instances of dbus-daemon and all running applications using the
  libdbus library must be restarted, or the system rebooted.");
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

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.1.2~16.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-devel", rpm:"dbus-devel~1.1.2~16.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-libs", rpm:"dbus-libs~1.1.2~16.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.1.2~16.el5_7", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
