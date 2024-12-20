# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871024");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-05-20 12:45:10 +0530 (Tue, 20 May 2014)");
  script_cve_id("CVE-2012-2664");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for sos RHSA-2013:1121-01");


  script_tag(name:"affected", value:"sos on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The sos package contains a set of tools that gather information from system
hardware, logs and configuration files. The information can then be used
for diagnostic purposes and debugging.

The sosreport utility collected the Kickstart configuration file
('/root/anaconda-ks.cfg'), but did not remove the root user's password from
it before adding the file to the resulting archive of debugging
information. An attacker able to access the archive could possibly use this
flaw to obtain the root user's password. '/root/anaconda-ks.cfg' usually
only contains a hash of the password, not the plain text password.
(CVE-2012-2664)

Note: This issue affected all installations, not only systems installed via
Kickstart. A '/root/anaconda-ks.cfg' file is created by all installation
types.

The utility also collects yum repository information from
'/etc/yum.repos.d' which in uncommon configurations may contain passwords.
Any http_proxy password specified in these files will now be automatically
removed. Passwords embedded within URLs in these files should be manually
removed or the files excluded from the archive.

All users of sos are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1121-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-July/msg00037.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~1.7~9.62.el5_9.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
