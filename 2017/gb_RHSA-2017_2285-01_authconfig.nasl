# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871849");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:58 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-7488");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for authconfig RHSA-2017:2285-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'authconfig'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The authconfig packages contain a
  command-line utility and a GUI application that can configure a workstation to
  be a client for certain network user information, authentication schemes, and
  other user information and authentication-related options. Security Fix(es): * A
  flaw was found where authconfig could configure sssd in a way that treats
  existing and non-existing logins differently, leaking information on existence
  of a user. An attacker with physical or network access to the machine could
  enumerate users via a timing attack. (CVE-2017-7488) This issue was discovered
  by Tomas Mraz (Red Hat) and Thorsten Scherf (Red Hat). Additional Changes: For
  detailed information on changes in this release, see the Red Hat Enterprise
  Linux 7.4 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"authconfig on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:2285-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00000.html");
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

  if ((res = isrpmvuln(pkg:"authconfig", rpm:"authconfig~6.2.8~30.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"authconfig-debuginfo", rpm:"authconfig-debuginfo~6.2.8~30.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"authconfig-gtk", rpm:"authconfig-gtk~6.2.8~30.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}