# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015899.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880887");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0344");
  script_cve_id("CVE-2009-0585");
  script_name("CentOS Update for evolution28-libsoup CESA-2009:0344 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution28-libsoup'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"evolution28-libsoup on CentOS 4");
  script_tag(name:"insight", value:"libsoup is an HTTP client/library implementation for GNOME written in C. It
  was originally part of a SOAP (Simple Object Access Protocol)
  implementation called Soup, but the SOAP and non-SOAP parts have now been
  split into separate packages.

  An integer overflow flaw which caused a heap-based buffer overflow was
  discovered in libsoup's Base64 encoding routine. An attacker could use this
  flaw to crash, or, possibly, execute arbitrary code. This arbitrary code
  would execute with the privileges of the application using libsoup's Base64
  routine to encode large, untrusted inputs. (CVE-2009-0585)

  All users of libsoup and evolution28-libsoup should upgrade to these
  updated packages, which contain a backported patch to resolve this issue.
  All running applications using the affected library function (such as
  Evolution configured to connect to the GroupWise back-end) must be
  restarted for the update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"evolution28-libsoup", rpm:"evolution28-libsoup~2.2.98~5.el4.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-libsoup-devel", rpm:"evolution28-libsoup-devel~2.2.98~5.el4.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.2.1~4.el4.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.2.1~4.el4.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
