# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871609");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-10 05:19:03 +0200 (Tue, 10 May 2016)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717",
                "CVE-2016-3718");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ImageMagick RHSA-2016:0726-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ImageMagick is an image display and
manipulation tool for the X Window System that can read and write multiple
image formats.

Security Fix(es):

  * It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the delegate functionality. A remote attacker
could create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the ImageMagick
utilities, would lead to arbitrary execution of shell commands with the
privileges of the user running the application. (CVE-2016-3714)

  * It was discovered that certain ImageMagick coders and pseudo-protocols
did not properly prevent security sensitive operations when processing
specially crafted images. A remote attacker could create a specially
crafted image that, when processed by an application using ImageMagick or
an unsuspecting user using the ImageMagick utilities, would allow the
attacker to delete, move, or disclose the contents of arbitrary files.
(CVE-2016-3715, CVE-2016-3716, CVE-2016-3717)

  * A server-side request forgery flaw was discovered in the way ImageMagick
processed certain images. A remote attacker could exploit this flaw to
mislead an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities into, for example, performing HTTP(S) requests or
opening FTP sessions via specially crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file that
disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT, and LABEL
coders. If you experience any problems after the update, it may be
necessary to manually adjust the policy.xml file to match your
requirements. Please take additional precautions to ensure that your
applications using the ImageMagick library do not process malicious or
untrusted files before doing so.");
  script_tag(name:"affected", value:"ImageMagick on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0726-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.8.9~13.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.8.9~13.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.7.8.9~13.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.7.8.9~13.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.2.7~4.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.2.7~4.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.7.2.7~4.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
