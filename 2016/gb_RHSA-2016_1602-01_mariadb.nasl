# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871652");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-08-12 05:47:11 +0200 (Fri, 12 Aug 2016)");
  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0643", "CVE-2016-0644",
                "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649",
                "CVE-2016-0650", "CVE-2016-0666", "CVE-2016-3452", "CVE-2016-3477",
                "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-5444");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mariadb RHSA-2016:1602-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"MariaDB is a multi-user, multi-threaded
SQL database server that is binary compatible with MySQL.

The following packages have been upgraded to a newer upstream version:
mariadb (5.5.50).

Security Fix(es):

  * This update fixes several vulnerabilities in the MariaDB database server.
Information about these flaws can be found on the Oracle Critical Patch
Update Advisory pages, listed in the References section. (CVE-2016-0640,
CVE-2016-0641, CVE-2016-0643, CVE-2016-0644, CVE-2016-0646, CVE-2016-0647,
CVE-2016-0648, CVE-2016-0649, CVE-2016-0650, CVE-2016-0666, CVE-2016-3452,
CVE-2016-3477, CVE-2016-3521, CVE-2016-3615, CVE-2016-5440, CVE-2016-5444)");
  script_tag(name:"affected", value:"mariadb on Red Hat Enterprise Linux
Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1602-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-August/msg00024.html");
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

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-bench", rpm:"mariadb-bench~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-devel", rpm:"mariadb-devel~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-libs", rpm:"mariadb-libs~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-server", rpm:"mariadb-server~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mariadb-test", rpm:"mariadb-test~5.5.50~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
