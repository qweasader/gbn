# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871858");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-08-04 12:48:01 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-10198", "CVE-2016-10199", "CVE-2016-9446", "CVE-2016-9810",
                "CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5838", "CVE-2017-5839",
                "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5842", "CVE-2017-5843",
                "CVE-2017-5844", "CVE-2017-5845", "CVE-2017-5848");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 18:59:00 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for GStreamer RHSA-2017:2060-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'GStreamer'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"GStreamer is a streaming media framework
  based on graphs of filters which operate on media data. The following packages
  have been upgraded to a later upstream version: clutter-gst2 (2.0.18),
  gnome-video-effects (0.4.3), gstreamer1 (1.10.4), gstreamer1-plugins-bad-free
  (1.10.4), gstreamer1-plugins-base (1.10.4), gstreamer1-plugins-good (1.10.4),
  orc (0.4.26). Security Fix(es): * Multiple flaws were found in gstreamer1,
  gstreamer1-plugins-base, gstreamer1-plugins-good, and
  gstreamer1-plugins-bad-free packages. An attacker could potentially use these
  flaws to crash applications which use the GStreamer framework. (CVE-2016-9446,
  CVE-2016-9810, CVE-2016-9811, CVE-2016-10198, CVE-2016-10199, CVE-2017-5837,
  CVE-2017-5838, CVE-2017-5839, CVE-2017-5840, CVE-2017-5841, CVE-2017-5842,
  CVE-2017-5843, CVE-2017-5844, CVE-2017-5845, CVE-2017-5848) Additional Changes:
  For detailed information on changes in this release, see the Red Hat Enterprise
  Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"GStreamer on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:2060-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00026.html");
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

  if ((res = isrpmvuln(pkg:"gnome-video-effects", rpm:"gnome-video-effects~0.4.3~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-gst2", rpm:"clutter-gst2~2.0.18~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-gst2-debuginfo", rpm:"clutter-gst2-debuginfo~2.0.18~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free", rpm:"gstreamer-plugins-bad-free~0.10.23~23.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-debuginfo", rpm:"gstreamer-plugins-bad-free-debuginfo~0.10.23~23.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~0.10.31~13.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good-debuginfo", rpm:"gstreamer-plugins-good-debuginfo~0.10.31~13.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1", rpm:"gstreamer1~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-debuginfo", rpm:"gstreamer1-debuginfo~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-devel", rpm:"gstreamer1-devel~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free", rpm:"gstreamer1-plugins-bad-free~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-bad-free-debuginfo", rpm:"gstreamer1-plugins-bad-free-debuginfo~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-base", rpm:"gstreamer1-plugins-base~1.10.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-base-debuginfo", rpm:"gstreamer1-plugins-base-debuginfo~1.10.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-base-devel", rpm:"gstreamer1-plugins-base-devel~1.10.4~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-good", rpm:"gstreamer1-plugins-good~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer1-plugins-good-debuginfo", rpm:"gstreamer1-plugins-good-debuginfo~1.10.4~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"orc", rpm:"orc~0.4.26~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"orc-debuginfo", rpm:"orc-debuginfo~0.4.26~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
