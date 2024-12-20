# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-October/msg00013.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870502");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_xref(name:"RHSA", value:"2011:1385-01");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-3365");
  script_name("RedHat Update for kdelibs and kdelibs3 RHSA-2011:1385-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs and kdelibs3'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"kdelibs and kdelibs3 on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kdelibs and kdelibs3 packages provide libraries for the K Desktop
  Environment (KDE).

  An input sanitization flaw was found in the KSSL (KDE SSL Wrapper) API. An
  attacker could supply a specially-crafted SSL certificate (for example, via
  a web page) to an application using KSSL, such as the Konqueror web
  browser, causing misleading information to be presented to the user,
  possibly tricking them into accepting the certificate as valid.
  (CVE-2011-3365)

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. The desktop must be restarted (log out, then
  log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.5.4~26.el5_7.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~3.5.4~26.el5_7.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.5.4~26.el5_7.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.5.4~26.el5_7.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~3.3.1~18.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-debuginfo", rpm:"kdelibs-debuginfo~3.3.1~18.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~3.3.1~18.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
