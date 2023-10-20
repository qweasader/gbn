# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871529");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-22 05:42:26 +0100 (Tue, 22 Dec 2015)");
  script_cve_id("CVE-2015-7501");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for jakarta-commons-collections RHSA-2015:2671-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jakarta-commons-collections'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Jakarta/Apache Commons Collections library
provides new interfaces,
implementations, and utilities to extend the features of the Java
Collections Framework.

It was found that the Apache commons-collections library permitted code
execution when deserializing objects involving a specially constructed
chain of classes. A remote attacker could use this flaw to execute
arbitrary code with the permissions of the application using the
commons-collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that require
those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to re-enable
their deserialization.

Further information about this security flaw may be found at the linked references.

All users of jakarta-commons-collections are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.
All running applications using the commons-collections library must be
restarted for the update to take effect.");
  script_tag(name:"affected", value:"jakarta-commons-collections on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2671-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-December/msg00052.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  script_xref(name:"URL", value:"https://access.redhat.com/solutions/2045023");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections", rpm:"jakarta-commons-collections~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-debuginfo", rpm:"jakarta-commons-collections-debuginfo~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-javadoc", rpm:"jakarta-commons-collections-javadoc~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-testframework", rpm:"jakarta-commons-collections-testframework~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-testframework-javadoc", rpm:"jakarta-commons-collections-testframework-javadoc~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-tomcat5", rpm:"jakarta-commons-collections-tomcat5~3.2~2jpp.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
