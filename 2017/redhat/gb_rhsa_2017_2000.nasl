# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871851");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:58 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-10207", "CVE-2017-5581", "CVE-2017-7392", "CVE-2017-7393",
                "CVE-2017-7394", "CVE-2017-7395", "CVE-2017-7396");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for tigervnc and fltk RHSA-2017:2000-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc and fltk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Virtual Network Computing (VNC) is a remote
  display system which allows users to view a computing desktop environment not
  only on the machine where it is running, but from anywhere on the Internet and
  from a wide variety of machine architectures. TigerVNC is a suite of VNC servers
  and clients which allows users to connect to other desktops running a VNC
  server. FLTK (pronounced 'fulltick') is a cross-platform C++ GUI toolkit. It
  provides modern GUI functionality without the bloat, and supports 3D graphics
  via OpenGL and its built-in GLUT emulation. The following packages have been
  upgraded to a later upstream version: tigervnc (1.8.0), fltk (1.3.4).
  (BZ#1388620, BZ#1413598) Security Fix(es): * A denial of service flaw was found
  in the TigerVNC's Xvnc server. A remote unauthenticated attacker could use this
  flaw to make Xvnc crash by terminating the TLS handshake process early.
  (CVE-2016-10207) * A double free flaw was found in the way TigerVNC handled
  ClientFence messages. A remote, authenticated attacker could use this flaw to
  make Xvnc crash by sending specially crafted ClientFence messages, resulting in
  denial of service. (CVE-2017-7393) * A missing input sanitization flaw was found
  in the way TigerVNC handled credentials. A remote unauthenticated attacker could
  use this flaw to make Xvnc crash by sending specially crafted usernames,
  resulting in denial of service. (CVE-2017-7394) * An integer overflow flaw was
  found in the way TigerVNC handled ClientCutText messages. A remote,
  authenticated attacker could use this flaw to make Xvnc crash by sending
  specially crafted ClientCutText messages, resulting in denial of service.
  (CVE-2017-7395) * A buffer overflow flaw, leading to memory corruption, was
  found in TigerVNC viewer. A remote malicious VNC server could use this flaw to
  crash the client vncviewer process resulting in denial of service.
  (CVE-2017-5581) * A memory leak flaw was found in the way TigerVNC handled
  termination of VeNCrypt connections. A remote unauthenticated attacker could
  repeatedly send connection requests to the Xvnc server, causing it to consume
  large amounts of memory resources over time, and ultimately leading to a denial
  of service due to memory exhaustion. (CVE-2017-7392) * A memory leak flaw was
  found in the way TigerVNC handled client connections. A remote unauthenticated
  attacker could repeatedly send connection requests to the Xvnc server, causing
  it to consume large amounts of memory resources over time, and ultimately
  leading to a denial of service due to memory exhaustion. (CVE-2017-7396)
  Additional Changes: For detailed information on changes in this release, see the
  Red Hat Enterprise Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"tigervnc and fltk on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:2000-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00024.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fltk", rpm:"fltk~1.3.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fltk-debuginfo", rpm:"fltk-debuginfo~1.3.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-debuginfo", rpm:"tigervnc-debuginfo~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.8.0~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}