# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871706");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-04 05:42:49 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-7050");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-16 12:03:00 +0000 (Fri, 16 Jun 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for resteasy-base RHSA-2016:2604-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'resteasy-base'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"RESTEasy contains a JBoss project that
provides frameworks to help build RESTful Web Services and RESTful Java
applications. It is a fully certified and portable implementation of the JAX-RS
specification.

Security Fix(es):

  * It was discovered that under certain conditions RESTEasy could be forced
to parse a request with SerializableProvider, resulting in deserialization
of potentially untrusted data. An attacker could possibly use this flaw to
execute arbitrary code with the permissions of the application using
RESTEasy. (CVE-2016-7050)

Red Hat would like to thank Mikhail Egorov (Odin) for reporting this issue.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"resteasy-base on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2604-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00040.html");
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

  if ((res = isrpmvuln(pkg:"resteasy-base-atom-provider", rpm:"resteasy-base-atom-provider~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-client", rpm:"resteasy-base-client~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jackson-provider", rpm:"resteasy-base-jackson-provider~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxb-provider", rpm:"resteasy-base-jaxb-provider~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs", rpm:"resteasy-base-jaxrs~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jaxrs-api", rpm:"resteasy-base-jaxrs-api~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"resteasy-base-jettison-provider", rpm:"resteasy-base-jettison-provider~3.0.6~4.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
