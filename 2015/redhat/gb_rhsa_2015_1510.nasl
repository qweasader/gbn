# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871418");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-03 15:08:04 +0530 (Mon, 03 Aug 2015)");
  script_cve_id("CVE-2015-3213");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for clutter RHSA-2015:1510-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'clutter'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Clutter is a library for creating fast, visually rich, graphical user
interfaces. Clutter is used for rendering the GNOME desktop environment.

A flaw was found in the way clutter processed certain mouse and touch
gestures. An attacker could use this flaw to bypass the screen lock.
(CVE-2015-3213)

All clutter users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, all applications using clutter must be restarted for the update to
take effect.");
  script_tag(name:"affected", value:"clutter on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1510-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00048.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"clutter", rpm:"clutter~1.14.4~12.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-debuginfo", rpm:"clutter-debuginfo~1.14.4~12.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}